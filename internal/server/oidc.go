package server

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
)

const (
	oidcStateCookieName = "oatd_oidc_state"
	oidcStateTTL        = 10 * time.Minute
)

type oidcProvider struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	tenantClaim  string
	roleClaim    string
	emailClaim   string
	scopes       []string
	stateKey     []byte
	discovery    oidcDiscovery
	httpClient   *http.Client
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcStatePayload struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	ReturnTo  string    `json:"return_to,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type oidcTokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type oidcJWKS struct {
	Keys []oidcJWK `json:"keys"`
}

type oidcJWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcJWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

func newOIDCProvider(issuerURL, clientID, clientSecret, redirectURL string, scopes []string, tenantClaim, roleClaim, emailClaim string, stateKey []byte) (*oidcProvider, error) {
	issuerURL = strings.TrimSpace(issuerURL)
	clientID = strings.TrimSpace(clientID)
	redirectURL = strings.TrimSpace(redirectURL)
	if issuerURL == "" || clientID == "" {
		return nil, nil
	}
	if redirectURL == "" {
		return nil, errors.New("oidc redirect url is required")
	}
	if len(stateKey) == 0 {
		return nil, errors.New("oidc state key is required")
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	discovery, err := fetchOIDCDiscovery(issuerURL)
	if err != nil {
		return nil, err
	}
	return &oidcProvider{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		tenantClaim:  defaultOIDCClaim(tenantClaim, "tenant"),
		roleClaim:    defaultOIDCClaim(roleClaim, "roles"),
		emailClaim:   defaultOIDCClaim(emailClaim, "email"),
		scopes:       append([]string(nil), scopes...),
		stateKey:     append([]byte(nil), stateKey...),
		discovery:    discovery,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p *oidcProvider) Enabled() bool {
	return p != nil && p.discovery.AuthorizationEndpoint != "" && p.discovery.TokenEndpoint != "" && p.discovery.JWKSURI != "" && p.clientID != ""
}

func (p *oidcProvider) BeginLogin(r *http.Request) (string, string, error) {
	if !p.Enabled() {
		return "", "", errors.New("oidc is not configured")
	}
	state := randomToken(24)
	nonce := randomToken(24)
	returnTo := sanitizeReturnTo(r.URL.Query().Get("return_to"))
	payload := oidcStatePayload{
		State:     state,
		Nonce:     nonce,
		ReturnTo:  returnTo,
		ExpiresAt: time.Now().UTC().Add(oidcStateTTL),
	}
	token, err := signOIDCState(p.stateKey, payload)
	if err != nil {
		return "", "", err
	}
	u, err := url.Parse(p.discovery.AuthorizationEndpoint)
	if err != nil {
		return "", "", err
	}
	query := u.Query()
	query.Set("response_type", "code")
	query.Set("client_id", p.clientID)
	query.Set("redirect_uri", p.redirectURL)
	query.Set("scope", strings.Join(p.scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	u.RawQuery = query.Encode()
	return u.String(), token, nil
}

func (p *oidcProvider) HandleCallback(ctx context.Context, r *http.Request) (auth.Principal, string, error) {
	if !p.Enabled() {
		return auth.Principal{}, "", errors.New("oidc is not configured")
	}
	if err := r.Context().Err(); err != nil {
		return auth.Principal{}, "", err
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		return auth.Principal{}, "", errors.New("missing authorization code")
	}
	stateToken, err := r.Cookie(oidcStateCookieName)
	if err != nil {
		return auth.Principal{}, "", errors.New("missing oidc state")
	}
	state, ok := verifyOIDCState(p.stateKey, stateToken.Value)
	if !ok {
		return auth.Principal{}, "", errors.New("invalid oidc state")
	}
	if time.Now().UTC().After(state.ExpiresAt) {
		return auth.Principal{}, "", errors.New("oidc state expired")
	}
	if subtle.ConstantTimeCompare([]byte(state.State), []byte(strings.TrimSpace(r.URL.Query().Get("state")))) != 1 {
		return auth.Principal{}, "", errors.New("oidc state mismatch")
	}
	token, err := p.exchangeCode(ctx, code)
	if err != nil {
		return auth.Principal{}, "", err
	}
	claims, err := p.verifyIDToken(token.IDToken, state.Nonce)
	if err != nil {
		return auth.Principal{}, "", err
	}
	principal := p.principalFromClaims(claims)
	if principal.Name == "" {
		return auth.Principal{}, "", errors.New("oidc principal is empty")
	}
	return principal, state.ReturnTo, nil
}

func (p *oidcProvider) exchangeCode(ctx context.Context, code string) (oidcTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.redirectURL)
	form.Set("client_id", p.clientID)
	if strings.TrimSpace(p.clientSecret) != "" {
		form.Set("client_secret", p.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return oidcTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.TrimSpace(p.clientSecret) != "" {
		req.SetBasicAuth(p.clientID, p.clientSecret)
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oidcTokenResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcTokenResponse{}, fmt.Errorf("oidc token exchange failed: %s", strings.TrimSpace(string(body)))
	}
	var token oidcTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return oidcTokenResponse{}, err
	}
	if strings.TrimSpace(token.IDToken) == "" {
		return oidcTokenResponse{}, errors.New("oidc token response missing id_token")
	}
	return token, nil
}

func (p *oidcProvider) verifyIDToken(idToken string, nonce string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid id token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header oidcJWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported oidc signing algorithm %s", header.Alg)
	}
	jwks, err := p.fetchJWKS()
	if err != nil {
		return nil, err
	}
	key, err := selectRSAKey(jwks, header.Kid)
	if err != nil {
		return nil, err
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	if issuer := claimString(claims, "iss"); issuer != p.discovery.Issuer {
		return nil, errors.New("oidc issuer mismatch")
	}
	if !claimHasAudience(claims["aud"], p.clientID) {
		return nil, errors.New("oidc audience mismatch")
	}
	if exp := claimUnix(claims["exp"]); exp > 0 && time.Now().UTC().After(time.Unix(exp, 0)) {
		return nil, errors.New("oidc token expired")
	}
	if nonce != "" && claimString(claims, "nonce") != nonce {
		return nil, errors.New("oidc nonce mismatch")
	}
	return claims, nil
}

func (p *oidcProvider) fetchJWKS() (oidcJWKS, error) {
	req, err := http.NewRequest(http.MethodGet, p.discovery.JWKSURI, nil)
	if err != nil {
		return oidcJWKS{}, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return oidcJWKS{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oidcJWKS{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcJWKS{}, fmt.Errorf("oidc jwks fetch failed: %s", strings.TrimSpace(string(body)))
	}
	var jwks oidcJWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return oidcJWKS{}, err
	}
	return jwks, nil
}

func (p *oidcProvider) principalFromClaims(claims map[string]any) auth.Principal {
	name := claimString(claims, p.emailClaim)
	if name == "" {
		name = claimString(claims, "preferred_username")
	}
	if name == "" {
		name = claimString(claims, "sub")
	}
	tenant := claimString(claims, p.tenantClaim)
	if tenant == "" {
		tenant = "default"
	}
	roles := claimStrings(claims, p.roleClaim)
	if len(roles) == 0 {
		roles = claimStrings(claims, "groups")
	}
	if len(roles) == 0 {
		roles = []string{auth.RoleViewer}
	}
	return auth.Principal{Name: name, Tenant: tenant, Roles: roles}
}

func fetchOIDCDiscovery(issuerURL string) (oidcDiscovery, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	req, err := http.NewRequest(http.MethodGet, issuerURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oidcDiscovery{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return oidcDiscovery{}, fmt.Errorf("oidc discovery failed: %s", strings.TrimSpace(string(body)))
	}
	var discovery oidcDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return oidcDiscovery{}, err
	}
	if discovery.Issuer == "" {
		discovery.Issuer = issuerURL
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.JWKSURI == "" {
		return oidcDiscovery{}, errors.New("oidc discovery missing endpoints")
	}
	return discovery, nil
}

func defaultOIDCClaim(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func randomToken(length int) string {
	if length <= 0 {
		length = 24
	}
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		sum := sha256.Sum256([]byte(time.Now().UTC().String()))
		return base64.RawURLEncoding.EncodeToString(sum[:])[:length]
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(raw), "=")
}

func sanitizeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "/"
	}
	return value
}

func signOIDCState(key []byte, payload oidcStatePayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyOIDCState(key []byte, token string) (oidcStatePayload, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return oidcStatePayload{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcStatePayload{}, false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcStatePayload{}, false
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(raw); err != nil {
		return oidcStatePayload{}, false
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), expected) != 1 {
		return oidcStatePayload{}, false
	}
	var payload oidcStatePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return oidcStatePayload{}, false
	}
	return payload, true
}

func claimString(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func claimStrings(claims map[string]any, key string) []string {
	value, ok := claims[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		parts := strings.FieldsFunc(v, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})
		return compactStrings(parts)
	case []any:
		values := make([]string, 0, len(v))
		for _, item := range v {
			values = append(values, strings.TrimSpace(fmt.Sprint(item)))
		}
		return compactStrings(values)
	default:
		return compactStrings([]string{strings.TrimSpace(fmt.Sprint(v))})
	}
}

func claimHasAudience(value any, audience string) bool {
	audience = strings.TrimSpace(audience)
	if audience == "" || value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) == audience
	case []any:
		for _, item := range v {
			if strings.TrimSpace(fmt.Sprint(item)) == audience {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if strings.TrimSpace(item) == audience {
				return true
			}
		}
	}
	return false
}

func claimUnix(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case json.Number:
		parsed, err := v.Int64()
		if err == nil {
			return parsed
		}
	}
	return 0
}

func compactStrings(values []string) []string {
	compact := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		compact = append(compact, value)
	}
	return compact
}

func selectRSAKey(jwks oidcJWKS, kid string) (*rsa.PublicKey, error) {
	var candidate *oidcJWK
	for i := range jwks.Keys {
		key := &jwks.Keys[i]
		if strings.TrimSpace(key.Kty) != "RSA" {
			continue
		}
		if kid != "" && key.Kid != kid {
			continue
		}
		candidate = key
		break
	}
	if candidate == nil {
		return nil, errors.New("oidc jwks key not found")
	}
	modulus, err := base64.RawURLEncoding.DecodeString(candidate.N)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(candidate.E)
	if err != nil {
		return nil, err
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, errors.New("invalid oidc jwks exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: exponent,
	}, nil
}
