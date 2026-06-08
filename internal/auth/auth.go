package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	RoleViewer      = "viewer"
	RoleIngestor    = "ingestor"
	RoleAnalyst     = "analyst"
	RoleOperator    = "operator"
	RoleAdmin       = "admin"
	loginBackoffCap = 1 * time.Minute
	loginAttemptTTL = 24 * time.Hour
)

type UserConfig struct {
	Name      string   `json:"name"`
	Tenant    string   `json:"tenant,omitempty"`
	TokenHash string   `json:"token_sha256"`
	Roles     []string `json:"roles"`
}

type Principal struct {
	Name   string   `json:"name"`
	Tenant string   `json:"tenant,omitempty"`
	Roles  []string `json:"roles"`
}

type SessionInfo struct {
	Principal Principal `json:"principal"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Authenticator struct {
	users      []UserConfig
	legacyHash string
	sessionTTL time.Duration
	sessionKey []byte
	loginMu    sync.Mutex
	logins     map[string]loginAttempt
}

type sessionPayload struct {
	Principal Principal `json:"principal"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}

type loginAttempt struct {
	Failures     int
	BlockedUntil time.Time
	LastSeen     time.Time
}

func New(users []UserConfig, legacyToken string) *Authenticator {
	authenticator := &Authenticator{
		users:      normalizeUsers(users),
		logins:     make(map[string]loginAttempt),
		sessionTTL: 12 * time.Hour,
	}
	if legacyToken != "" {
		authenticator.legacyHash = HashToken(legacyToken)
	}
	authenticator.sessionKey = deriveSessionKey(os.Getenv("OATD_SESSION_SECRET"))
	return authenticator
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *Authenticator) Enabled() bool {
	return len(a.users) > 0 || a.legacyHash != ""
}

func (a *Authenticator) HasUsers() bool {
	return len(a.users) > 0
}

func (a *Authenticator) LoginRetryAfter(key string) time.Duration {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0
	}

	now := time.Now().UTC()
	a.loginMu.Lock()
	defer a.loginMu.Unlock()

	a.pruneLoginAttemptsLocked(now)
	attempt, ok := a.logins[key]
	if !ok || attempt.BlockedUntil.IsZero() || !now.Before(attempt.BlockedUntil) {
		return 0
	}
	return time.Until(attempt.BlockedUntil)
}

func (a *Authenticator) RecordLoginAttempt(key string, success bool) time.Duration {
	key = strings.TrimSpace(key)
	if key == "" {
		return 0
	}

	now := time.Now().UTC()
	a.loginMu.Lock()
	defer a.loginMu.Unlock()

	a.pruneLoginAttemptsLocked(now)
	if success {
		delete(a.logins, key)
		return 0
	}

	attempt := a.logins[key]
	if attempt.Failures < 0 {
		attempt.Failures = 0
	}
	attempt.Failures++
	if attempt.Failures > 8 {
		attempt.Failures = 8
	}
	delay := time.Second << (attempt.Failures - 1)
	if delay > loginBackoffCap {
		delay = loginBackoffCap
	}
	attempt.BlockedUntil = now.Add(delay)
	attempt.LastSeen = now
	a.logins[key] = attempt
	return delay
}

func (a *Authenticator) Authenticate(r *http.Request) (Principal, bool) {
	if principal, ok := a.authenticateSession(r); ok {
		return principal, true
	}
	token := readToken(r)
	if token == "" {
		return Principal{}, false
	}
	tokenHash := HashToken(token)
	principal, ok := a.principalForToken(tokenHash)
	if ok {
		return principal, true
	}
	return Principal{}, false
}

func (a *Authenticator) Login(username string, token string) (SessionInfo, string, bool) {
	principal, ok := a.principalForCredentials(username, token)
	if !ok {
		return SessionInfo{}, "", false
	}
	return a.MintSession(principal)
}

func (a *Authenticator) MintSession(principal Principal) (SessionInfo, string, bool) {
	principal.Tenant = strings.TrimSpace(principal.Tenant)
	if principal.Tenant == "" {
		principal.Tenant = "default"
	}
	principal.Roles = normalizeRoles(principal.Roles)
	if len(principal.Roles) == 0 {
		principal.Roles = []string{RoleViewer}
	}
	info := SessionInfo{
		Principal: principal,
		ExpiresAt: time.Now().UTC().Add(a.sessionTTL),
	}
	sessionID, err := a.issueSession(info)
	if err != nil {
		return SessionInfo{}, "", false
	}
	return info, sessionID, true
}

func (a *Authenticator) Session(r *http.Request) (SessionInfo, bool) {
	sessionToken := readSessionID(r)
	if sessionToken == "" {
		return SessionInfo{}, false
	}
	info, ok := a.parseSession(sessionToken)
	if !ok || time.Now().UTC().After(info.ExpiresAt) {
		return SessionInfo{}, false
	}
	return info, true
}

func (a *Authenticator) Logout(r *http.Request) bool {
	sessionToken := readSessionID(r)
	if sessionToken == "" {
		return false
	}
	_, ok := a.parseSession(sessionToken)
	return ok
}

func (a *Authenticator) SessionKey() []byte {
	if len(a.sessionKey) == 0 {
		return nil
	}
	return append([]byte(nil), a.sessionKey...)
}

func (p Principal) HasAny(roles ...string) bool {
	for _, have := range p.Roles {
		for _, want := range roles {
			if have == RoleAdmin || have == want {
				return true
			}
		}
	}
	return false
}

func (a *Authenticator) SetSessionCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Authenticator) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func RequiredRoles(method string, path string) []string {
	if path == "/api/audit" {
		return []string{RoleAnalyst, RoleOperator}
	}
	if path == "/api/audit/chain" {
		return []string{RoleAnalyst, RoleOperator}
	}
	if path == "/api/gateway/decide" {
		return []string{RoleIngestor, RoleAnalyst, RoleOperator}
	}
	if path == "/api/gateway/execute" {
		return []string{RoleIngestor, RoleAnalyst, RoleOperator}
	}
	if path == "/api/gateway/proxy" {
		return []string{RoleIngestor, RoleAnalyst, RoleOperator}
	}
	if path == "/api/mcp/proxy" {
		return []string{RoleIngestor, RoleAnalyst, RoleOperator}
	}
	if path == "/api/gateway/queue" || strings.HasPrefix(path, "/api/gateway/actions/") {
		return []string{RoleAnalyst, RoleOperator}
	}
	if strings.HasPrefix(path, "/api/deception") {
		return []string{RoleOperator}
	}
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		return []string{RoleViewer, RoleAnalyst, RoleOperator, RoleIngestor}
	}
	if path == "/api/events" || path == "/api/demo" {
		return []string{RoleIngestor, RoleAnalyst, RoleOperator}
	}
	if strings.HasPrefix(path, "/api/responses/approve") {
		return []string{RoleOperator}
	}
	if strings.HasPrefix(path, "/api/responses") {
		return []string{RoleAnalyst, RoleOperator}
	}
	return []string{RoleAdmin}
}

func normalizeUsers(users []UserConfig) []UserConfig {
	normalized := make([]UserConfig, 0, len(users))
	for _, user := range users {
		user.Name = strings.TrimSpace(user.Name)
		user.Tenant = strings.TrimSpace(user.Tenant)
		if user.Tenant == "" {
			user.Tenant = "default"
		}
		user.TokenHash = strings.ToLower(strings.TrimSpace(user.TokenHash))
		if user.Name == "" || user.TokenHash == "" {
			continue
		}
		user.Roles = normalizeRoles(user.Roles)
		if len(user.Roles) == 0 {
			user.Roles = []string{RoleViewer}
		}
		normalized = append(normalized, user)
	}
	return normalized
}

var knownRoles = map[string]struct{}{
	RoleViewer:   {},
	RoleIngestor: {},
	RoleAnalyst:  {},
	RoleOperator: {},
	RoleAdmin:    {},
}

func normalizeRoles(roles []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		// Only honor roles in the known application set. IdP/SSO role and group
		// claims are attacker-influenceable, so an unmapped or injected role
		// string must not silently grant access.
		if _, ok := knownRoles[role]; !ok {
			continue
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		normalized = append(normalized, role)
	}
	return normalized
}

func (a *Authenticator) principalForCredentials(username string, token string) (Principal, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, false
	}
	tokenHash := HashToken(token)
	username = strings.TrimSpace(username)
	if principal, ok := a.principalForToken(tokenHash); ok {
		if username != "" && !strings.EqualFold(username, principal.Name) && principal.Name != "legacy-token" {
			return Principal{}, false
		}
		return principal, true
	}
	return Principal{}, false
}

func (a *Authenticator) principalForToken(tokenHash string) (Principal, bool) {
	for _, user := range a.users {
		if constantTimeEqual(tokenHash, user.TokenHash) {
			return Principal{Name: user.Name, Tenant: user.Tenant, Roles: user.Roles}, true
		}
	}
	if a.legacyHash != "" && constantTimeEqual(tokenHash, a.legacyHash) {
		return Principal{Name: "legacy-token", Tenant: "default", Roles: []string{RoleAdmin}}, true
	}
	return Principal{}, false
}

func readToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-OATD-Token"))
}

func readSessionID(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (a *Authenticator) authenticateSession(r *http.Request) (Principal, bool) {
	info, ok := a.Session(r)
	if !ok {
		return Principal{}, false
	}
	return info.Principal, true
}

func (a *Authenticator) pruneLoginAttemptsLocked(now time.Time) {
	for key, attempt := range a.logins {
		if attempt.LastSeen.IsZero() {
			attempt.LastSeen = attempt.BlockedUntil
		}
		if !attempt.LastSeen.IsZero() && now.Sub(attempt.LastSeen) > loginAttemptTTL {
			delete(a.logins, key)
		}
	}
}

const sessionCookieName = "oatd_session"

func constantTimeEqual(got string, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func deriveSessionKey(explicitSecret string) []byte {
	if value := strings.TrimSpace(explicitSecret); value != "" {
		sum := sha256.Sum256([]byte(value))
		return sum[:]
	}
	return nil
}

func (a *Authenticator) issueSession(info SessionInfo) (string, error) {
	if len(a.sessionKey) == 0 {
		return "", errors.New("session key is not configured")
	}
	payload := sessionPayload{
		Principal: info.Principal,
		ExpiresAt: info.ExpiresAt.UTC(),
		IssuedAt:  time.Now().UTC(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	session, err := signSession(a.sessionKey, data)
	if err != nil {
		return "", err
	}
	return session, nil
}

func (a *Authenticator) parseSession(token string) (SessionInfo, bool) {
	if len(a.sessionKey) == 0 {
		return SessionInfo{}, false
	}
	data, ok := verifySession(a.sessionKey, token)
	if !ok {
		return SessionInfo{}, false
	}
	var payload sessionPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return SessionInfo{}, false
	}
	if payload.Principal.Name == "" {
		return SessionInfo{}, false
	}
	return SessionInfo{
		Principal: payload.Principal,
		ExpiresAt: payload.ExpiresAt,
	}, true
}

func signSession(key []byte, payload []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(payload); err != nil {
		return "", err
	}
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifySession(key []byte, token string) ([]byte, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	expected, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(payload); err != nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), expected) != 1 {
		return nil, false
	}
	return payload, true
}
