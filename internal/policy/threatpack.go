package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const DefaultThreatPackVersion = "2026.06"

type ThreatPack struct {
	Name                string                  `json:"name"`
	Version             string                  `json:"version"`
	ApprovedTools       []string                `json:"approved_tools"`
	ApprovedEgressHosts []string                `json:"approved_egress_hosts"`
	Rules               []domain.RuleDescriptor `json:"rules"`
}

func DefaultThreatPack() ThreatPack {
	pack := ThreatPack{
		Name:    "builtin",
		Version: DefaultThreatPackVersion,
		ApprovedTools: []string{
			"asset_inventory",
			"ticket_create",
			"policy_read",
			"siem_search",
		},
		ApprovedEgressHosts: []string{
			"api.openai.com",
			"github.com",
			"login.microsoftonline.com",
		},
	}
	pack.Rules = defaultRuleDescriptors(pack.Name, pack.Version)
	return pack
}

func LoadThreatPack(path string) (ThreatPack, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultThreatPack(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ThreatPack{}, err
	}
	if err := verifyThreatPackSignature(path, data); err != nil {
		return ThreatPack{}, err
	}
	var pack ThreatPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return ThreatPack{}, err
	}
	if pack.Name == "" {
		pack.Name = "custom"
	}
	if pack.Version == "" {
		pack.Version = DefaultThreatPackVersion
	}
	if len(pack.ApprovedTools) == 0 {
		pack.ApprovedTools = DefaultThreatPack().ApprovedTools
	}
	if len(pack.ApprovedEgressHosts) == 0 {
		pack.ApprovedEgressHosts = DefaultThreatPack().ApprovedEgressHosts
	}
	if len(pack.Rules) == 0 {
		pack.Rules = defaultRuleDescriptors(pack.Name, pack.Version)
	} else {
		for i := range pack.Rules {
			pack.Rules[i].PackName = pack.Name
			pack.Rules[i].PackVersion = pack.Version
		}
	}
	return pack, nil
}

func defaultRuleDescriptors(packName string, packVersion string) []domain.RuleDescriptor {
	rules := []domain.RuleDescriptor{
		{
			ID:          "agent.tool.unapproved",
			Name:        "Unapproved agent tool call",
			Description: "Flags AI-agent or MCP tool calls outside the approved tool manifest.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"agent_tool_call", "tool_manifest"},
		},
		{
			ID:          "agent.secret.exposure",
			Name:        "Potential secret exposure through agent context",
			Description: "Flags commands and tool calls that combine agent activity with token, secret, or environment access.",
			Severity:    domain.SeverityCritical,
			Signals:     []string{"agent_tool_call", "secret", "token", "environment"},
		},
		{
			ID:          "network.egress.unknown",
			Name:        "Unknown outbound destination",
			Description: "Flags non-private outbound network flows to destinations outside the approved egress list.",
			Severity:    domain.SeverityMedium,
			Signals:     []string{"network_flow", "egress"},
		},
		{
			ID:          "process.discovery.chain",
			Name:        "Suspicious discovery process",
			Description: "Flags process commands commonly seen during discovery, credential access, or lateral movement.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"process_start", "discovery", "credential_access"},
		},
		{
			ID:          "deception.canary.hit",
			Name:        "Canary or deception asset touched",
			Description: "Flags interaction with a decoy token, honey credential, or instrumented deception service.",
			Severity:    domain.SeverityCritical,
			Signals:     []string{"deception_hit", "canary"},
		},
		{
			ID:          "model.runtime.suspicious",
			Name:        "Suspicious local model runtime behavior",
			Description: "Flags local model runtime activity combined with unexpected downloads, shelling out, or external egress.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"model_runtime", "gpu", "download", "shell"},
		},
	}
	for i := range rules {
		rules[i].PackName = packName
		rules[i].PackVersion = packVersion
	}
	return rules
}

func (p ThreatPack) Validate() error {
	if strings.TrimSpace(p.Version) == "" {
		return errors.New("threat pack version is required")
	}
	return nil
}

// manifestHMACKey returns the key used to sign/verify threat-pack manifests.
// It is a local, host-held secret (env), not a CI/GitHub secret.
func manifestHMACKey() []byte {
	secret := strings.TrimSpace(os.Getenv("OATD_MANIFEST_HMAC_SECRET"))
	if secret == "" {
		return nil
	}
	return []byte(secret)
}

func manifestSignatureRequired() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OATD_MANIFEST_REQUIRE_SIGNED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ManifestSignature returns the hex HMAC-SHA256 of the manifest bytes.
func ManifestSignature(data []byte, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignThreatPackFile signs the manifest at path with OATD_MANIFEST_HMAC_SECRET
// and writes a detached signature to path + ".sig". It returns the signature
// file path.
func SignThreatPackFile(path string) (string, error) {
	key := manifestHMACKey()
	if len(key) == 0 {
		return "", errors.New("OATD_MANIFEST_HMAC_SECRET is required to sign a manifest")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sigPath := path + ".sig"
	if err := os.WriteFile(sigPath, []byte(ManifestSignature(data, key)+"\n"), 0o600); err != nil {
		return "", err
	}
	return sigPath, nil
}

// verifyThreatPackSignature enforces manifest integrity. By default it is
// opt-in: verification runs only when both a key and a detached signature are
// present. With OATD_MANIFEST_REQUIRE_SIGNED set, an unsigned or unverifiable
// manifest is rejected.
func verifyThreatPackSignature(path string, data []byte) error {
	key := manifestHMACKey()
	required := manifestSignatureRequired()
	sigPath := path + ".sig"
	sigBytes, sigErr := os.ReadFile(sigPath)

	// If a signing key is configured, signatures are enforced: a missing or
	// invalid signature fails closed. Previously a missing .sig silently skipped
	// verification even when a key was set, so a tampered manifest could load.
	if len(key) > 0 {
		if sigErr != nil {
			return fmt.Errorf("threat pack signature %q is missing but a signing key is configured: %w", sigPath, sigErr)
		}
		expected := ManifestSignature(data, key)
		provided := strings.TrimSpace(string(sigBytes))
		if !hmac.Equal([]byte(expected), []byte(provided)) {
			return fmt.Errorf("threat pack signature mismatch for %q", path)
		}
		return nil
	}

	// No signing key configured.
	if required {
		return errors.New("signed manifest required but OATD_MANIFEST_HMAC_SECRET is not set")
	}
	log.Printf("warning: loading threat pack %q without signature verification; set OATD_MANIFEST_HMAC_SECRET to enforce", path)
	return nil
}
