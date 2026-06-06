package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
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

type Authenticator struct {
	users      []UserConfig
	legacyHash string
}

func New(users []UserConfig, legacyToken string) *Authenticator {
	authenticator := &Authenticator{users: normalizeUsers(users)}
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
	token := readToken(r)
	if token == "" {
		return Principal{}, false
	}
	tokenHash := HashToken(token)
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

func RequiredRoles(method string, path string) []string {
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

func readToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-OATD-Token"))
}

func constantTimeEqual(got string, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
