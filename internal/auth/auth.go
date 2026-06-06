package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	RoleViewer   = "viewer"
	RoleIngestor = "ingestor"
	RoleAnalyst  = "analyst"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

type UserConfig struct {
	Name      string   `json:"name"`
	TokenHash string   `json:"token_sha256"`
	Roles     []string `json:"roles"`
}

type Principal struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type SessionInfo struct {
	Principal Principal `json:"principal"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Authenticator struct {
	users      []UserConfig
	legacyHash string
	sessionMu  sync.RWMutex
	sessions   map[string]SessionInfo
	sessionTTL time.Duration
}

func New(users []UserConfig, legacyToken string) *Authenticator {
	authenticator := &Authenticator{
		users:      normalizeUsers(users),
		sessions:   make(map[string]SessionInfo),
		sessionTTL: 12 * time.Hour,
	}
	if legacyToken != "" {
		authenticator.legacyHash = HashToken(legacyToken)
	}
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
	sessionID := randomSessionID()
	if sessionID == "" {
		return SessionInfo{}, "", false
	}
	info := SessionInfo{
		Principal: principal,
		ExpiresAt: time.Now().UTC().Add(a.sessionTTL),
	}
	a.sessionMu.Lock()
	a.sessions[sessionID] = info
	a.sessionMu.Unlock()
	return info, sessionID, true
}

func (a *Authenticator) Session(r *http.Request) (SessionInfo, bool) {
	sessionID := readSessionID(r)
	if sessionID == "" {
		return SessionInfo{}, false
	}
	a.sessionMu.RLock()
	info, ok := a.sessions[sessionID]
	a.sessionMu.RUnlock()
	if !ok || time.Now().UTC().After(info.ExpiresAt) {
		if ok {
			a.sessionMu.Lock()
			delete(a.sessions, sessionID)
			a.sessionMu.Unlock()
		}
		return SessionInfo{}, false
	}
	return info, true
}

func (a *Authenticator) Logout(r *http.Request) bool {
	sessionID := readSessionID(r)
	if sessionID == "" {
		return false
	}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	if _, ok := a.sessions[sessionID]; !ok {
		return false
	}
	delete(a.sessions, sessionID)
	return true
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

func normalizeRoles(roles []string) []string {
	seen := map[string]struct{}{}
	normalized := []string{}
	for _, role := range roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
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
			return Principal{Name: user.Name, Roles: user.Roles}, true
		}
	}
	if a.legacyHash != "" && constantTimeEqual(tokenHash, a.legacyHash) {
		return Principal{Name: "legacy-token", Roles: []string{RoleAdmin}}, true
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

func randomSessionID() string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

const sessionCookieName = "oatd_session"

func constantTimeEqual(got string, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
