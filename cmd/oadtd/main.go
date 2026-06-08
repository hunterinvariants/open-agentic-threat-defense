package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/config"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
	"github.com/open-agentic-threat-defense/oadtd/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	webDir := flag.String("web", "web", "static dashboard directory")
	dataPath := flag.String("data", "", "optional JSON snapshot path for local persistence")
	postgresDSN := flag.String("postgres-dsn", os.Getenv("OATD_POSTGRES_DSN"), "Postgres DSN for production persistence")
	policyPath := flag.String("policy", "", "optional JSON policy configuration path")
	apiToken := flag.String("api-token", os.Getenv("OATD_API_TOKEN"), "optional API token for write endpoints")
	threatPackPath := flag.String("threat-pack", os.Getenv("OATD_THREAT_PACK"), "optional threat pack JSON file")
	deceptionTokensPath := flag.String("deception-tokens", os.Getenv("OATD_DECEPTION_TOKENS"), "optional JSON file of deception/canary tokens")
	tenantPoliciesPath := flag.String("tenant-policies", os.Getenv("OATD_TENANT_POLICIES"), "optional JSON file of org-scoped policy sets")
	licenseFile := flag.String("license-file", os.Getenv("OATD_LICENSE_FILE"), "path to a commercial license token file")
	licensePublicKey := flag.String("license-public-key", os.Getenv("OATD_LICENSE_PUBLIC_KEY"), "base64 ed25519 public key to verify the license")
	alertWebhookURL := flag.String("alert-webhook-url", os.Getenv("OATD_ALERT_WEBHOOK_URL"), "optional SIEM/webhook URL for new alerts")
	alertWebhookToken := flag.String("alert-webhook-token", os.Getenv("OATD_ALERT_WEBHOOK_TOKEN"), "optional bearer token for alert webhook")
	ticketWebhookURL := flag.String("ticket-webhook-url", os.Getenv("OATD_TICKET_WEBHOOK_URL"), "optional webhook URL for incident ticket creation")
	ticketWebhookToken := flag.String("ticket-webhook-token", os.Getenv("OATD_TICKET_WEBHOOK_TOKEN"), "optional bearer token for ticket webhook")
	responseWebhookURL := flag.String("response-webhook-url", os.Getenv("OATD_RESPONSE_WEBHOOK_URL"), "optional webhook URL for approved response actions")
	responseWebhookToken := flag.String("response-webhook-token", os.Getenv("OATD_RESPONSE_WEBHOOK_TOKEN"), "optional bearer token for response webhook")
	githubAPIBaseURL := flag.String("github-api-base", os.Getenv("OATD_GITHUB_API_BASE"), "optional GitHub API base URL")
	githubOwner := flag.String("github-owner", os.Getenv("OATD_GITHUB_OWNER"), "GitHub owner for issue and workflow integrations")
	githubRepo := flag.String("github-repo", os.Getenv("OATD_GITHUB_REPO"), "GitHub repository for issue and workflow integrations")
	githubToken := flag.String("github-token", os.Getenv("OATD_GITHUB_TOKEN"), "GitHub token for issue and workflow integrations")
	githubWorkflowFile := flag.String("github-workflow-file", os.Getenv("OATD_GITHUB_WORKFLOW_FILE"), "GitHub workflow file for approved response actions")
	githubWorkflowRef := flag.String("github-workflow-ref", os.Getenv("OATD_GITHUB_WORKFLOW_REF"), "GitHub ref for workflow dispatch")
	jiraBaseURL := flag.String("jira-base-url", os.Getenv("OATD_JIRA_BASE_URL"), "Jira base URL for incident tickets")
	jiraEmail := flag.String("jira-email", os.Getenv("OATD_JIRA_EMAIL"), "Jira account email")
	jiraAPIToken := flag.String("jira-api-token", os.Getenv("OATD_JIRA_API_TOKEN"), "Jira API token")
	jiraProjectKey := flag.String("jira-project-key", os.Getenv("OATD_JIRA_PROJECT_KEY"), "Jira project key for incidents")
	jiraIssueType := flag.String("jira-issue-type", os.Getenv("OATD_JIRA_ISSUE_TYPE"), "Jira issue type (default Task)")
	servicenowURL := flag.String("servicenow-url", os.Getenv("OATD_SERVICENOW_URL"), "ServiceNow instance URL for incidents")
	servicenowUser := flag.String("servicenow-user", os.Getenv("OATD_SERVICENOW_USER"), "ServiceNow user")
	servicenowPassword := flag.String("servicenow-password", os.Getenv("OATD_SERVICENOW_PASSWORD"), "ServiceNow password")
	mcpUpstreamURL := flag.String("mcp-upstream-url", os.Getenv("OATD_MCP_UPSTREAM_URL"), "upstream MCP server URL for transparent interception")
	mcpUpstreamToken := flag.String("mcp-upstream-token", os.Getenv("OATD_MCP_UPSTREAM_TOKEN"), "optional bearer token for MCP upstream")
	proxyAllowLocalTargets := flag.Bool("proxy-allow-local-targets", parseBoolEnv(os.Getenv("OATD_PROXY_ALLOW_LOCAL_TARGETS")), "allow the gateway proxy to reach loopback/private/internal upstreams (DANGEROUS; off by default)")
	oidcIssuerURL := flag.String("oidc-issuer-url", os.Getenv("OATD_OIDC_ISSUER_URL"), "OIDC issuer URL for SSO login")
	oidcClientID := flag.String("oidc-client-id", os.Getenv("OATD_OIDC_CLIENT_ID"), "OIDC client ID")
	oidcClientSecret := flag.String("oidc-client-secret", os.Getenv("OATD_OIDC_CLIENT_SECRET"), "OIDC client secret")
	oidcRedirectURL := flag.String("oidc-redirect-url", os.Getenv("OATD_OIDC_REDIRECT_URL"), "OIDC redirect URL")
	oidcScopes := flag.String("oidc-scopes", defaultString(os.Getenv("OATD_OIDC_SCOPES"), "openid,profile,email"), "comma-separated OIDC scopes")
	oidcTenantClaim := flag.String("oidc-tenant-claim", os.Getenv("OATD_OIDC_TENANT_CLAIM"), "OIDC claim name for tenant assignment")
	oidcRoleClaim := flag.String("oidc-role-claim", os.Getenv("OATD_OIDC_ROLE_CLAIM"), "OIDC claim name for roles")
	oidcEmailClaim := flag.String("oidc-email-claim", os.Getenv("OATD_OIDC_EMAIL_CLAIM"), "OIDC claim name for user name/email")
	samlRootURL := flag.String("saml-root-url", os.Getenv("OATD_SAML_ROOT_URL"), "SAML service provider root URL")
	samlIDPMetadataURL := flag.String("saml-idp-metadata-url", os.Getenv("OATD_SAML_IDP_METADATA_URL"), "SAML identity provider metadata URL")
	samlKeyPath := flag.String("saml-key-path", os.Getenv("OATD_SAML_KEY_PATH"), "SAML signing key path")
	samlCertPath := flag.String("saml-cert-path", os.Getenv("OATD_SAML_CERT_PATH"), "SAML signing certificate path")
	samlTenantAttribute := flag.String("saml-tenant-attribute", os.Getenv("OATD_SAML_TENANT_ATTRIBUTE"), "SAML attribute name for tenant assignment")
	samlRoleAttribute := flag.String("saml-role-attribute", os.Getenv("OATD_SAML_ROLE_ATTRIBUTE"), "SAML attribute name for roles")
	samlEmailAttribute := flag.String("saml-email-attribute", os.Getenv("OATD_SAML_EMAIL_ATTRIBUTE"), "SAML attribute name for user name/email")
	publicURL := flag.String("public-url", os.Getenv("OATD_PUBLIC_URL"), "public URL for HA and SSO callbacks")
	instanceName := flag.String("instance-name", os.Getenv("OATD_INSTANCE_NAME"), "instance name for HA deployments")
	tenantIsolationMode := flag.String("tenant-isolation-mode", defaultString(os.Getenv("OATD_TENANT_ISOLATION_MODE"), "logical"), "tenant isolation mode: logical or physical")
	tenantRegistryPath := flag.String("tenant-registry-path", os.Getenv("OATD_TENANT_REGISTRY_PATH"), "path to tenant registry JSON")
	tenantPostgresDSNTemplate := flag.String("tenant-postgres-dsn-template", os.Getenv("OATD_TENANT_POSTGRES_DSN_TEMPLATE"), "Postgres DSN template for physical tenant stores")
	tenantDataPathTemplate := flag.String("tenant-data-path-template", os.Getenv("OATD_TENANT_DATA_PATH_TEMPLATE"), "file path template for physical tenant stores")
	trustedProxies := flag.String("trusted-proxies", os.Getenv("OATD_TRUSTED_PROXIES"), "comma-separated list of trusted proxy CIDRs or IPs")
	retentionWindow := flag.String("retention-window", defaultString(os.Getenv("OATD_RETENTION_WINDOW"), "30d"), "retention window for events, alerts, actions, and audits")
	gatewayMaxInFlight := flag.Int("gateway-max-in-flight", defaultIntEnv(os.Getenv("OATD_GATEWAY_MAX_IN_FLIGHT"), 64), "max in-flight gateway operations before backpressure")
	validationResultPath := flag.String("validation-result-path", os.Getenv("OATD_VALIDATION_RESULT_PATH"), "path to the detection-validation result JSON served at /api/gateway/validation")
	validationHistoryPath := flag.String("validation-history-path", os.Getenv("OATD_VALIDATION_HISTORY_PATH"), "path to the detection-validation history JSONL for the dashboard trend")
	insecure := flag.Bool("insecure", parseBoolEnv(os.Getenv("OATD_INSECURE")), "allow open mode on non-loopback listen addresses")
	withDemo := flag.Bool("demo", false, "load safe demo telemetry at startup")
	flag.Parse()

	runtimeConfig, err := config.Load(*policyPath)
	if err != nil {
		log.Fatal(err)
	}
	if value := strings.TrimSpace(*threatPackPath); value != "" {
		runtimeConfig.ThreatPackPath = value
	}
	authConfigured := len(runtimeConfig.Users) > 0 ||
		strings.TrimSpace(*apiToken) != "" ||
		strings.TrimSpace(*oidcIssuerURL) != "" ||
		strings.TrimSpace(*oidcClientID) != "" ||
		strings.TrimSpace(*oidcClientSecret) != "" ||
		strings.TrimSpace(*oidcRedirectURL) != "" ||
		strings.TrimSpace(*samlRootURL) != "" ||
		strings.TrimSpace(*samlIDPMetadataURL) != "" ||
		strings.TrimSpace(*samlKeyPath) != "" ||
		strings.TrimSpace(*samlCertPath) != ""
	if err := server.ValidateListenAddress(*addr, authConfigured, *insecure); err != nil {
		log.Fatal(err)
	}
	if authConfigured && strings.TrimSpace(os.Getenv("OATD_SESSION_SECRET")) == "" {
		log.Fatal("OATD_SESSION_SECRET is required when authentication or SSO is configured")
	}
	window, err := runtimeConfig.CorrelationWindowDuration()
	if err != nil {
		log.Fatal(err)
	}
	policyConfig, err := runtimeConfig.PolicyConfig()
	if err != nil {
		log.Fatal(err)
	}
	var deceptionTokens []domain.DeceptionToken
	if value := strings.TrimSpace(*deceptionTokensPath); value != "" {
		data, err := os.ReadFile(value)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.Unmarshal(data, &deceptionTokens); err != nil {
			log.Fatal(err)
		}
	}
	var tenantPolicies []policy.TenantPolicy
	if value := strings.TrimSpace(*tenantPoliciesPath); value != "" {
		data, err := os.ReadFile(value)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.Unmarshal(data, &tenantPolicies); err != nil {
			log.Fatal(err)
		}
	}
	licenseToken := ""
	if value := strings.TrimSpace(*licenseFile); value != "" {
		data, err := os.ReadFile(value)
		if err != nil {
			log.Fatal(err)
		}
		licenseToken = strings.TrimSpace(string(data))
	}
	retention, err := parseFlexibleDuration(strings.TrimSpace(*retentionWindow))
	if err != nil {
		log.Fatal(err)
	}

	app, err := server.NewWithOptions(server.Options{
		WebDir:                    *webDir,
		DataPath:                  *dataPath,
		PostgresDSN:               *postgresDSN,
		APIToken:                  *apiToken,
		Users:                     runtimeConfig.Users,
		Policy:                    policyConfig,
		PolicyPath:                strings.TrimSpace(*policyPath),
		ValidationResultPath:      strings.TrimSpace(*validationResultPath),
		ValidationHistoryPath:     strings.TrimSpace(*validationHistoryPath),
		CorrelationWindow:         window,
		ThreatPackPath:            strings.TrimSpace(*threatPackPath),
		DeceptionTokens:           deceptionTokens,
		TenantPolicies:            tenantPolicies,
		LicenseToken:              licenseToken,
		LicensePublicKey:          strings.TrimSpace(*licensePublicKey),
		AlertWebhookURL:           *alertWebhookURL,
		AlertWebhookToken:         *alertWebhookToken,
		TicketWebhookURL:          *ticketWebhookURL,
		TicketWebhookToken:        *ticketWebhookToken,
		ResponseWebhookURL:        *responseWebhookURL,
		ResponseWebhookToken:      *responseWebhookToken,
		GitHubAPIBaseURL:          *githubAPIBaseURL,
		GitHubOwner:               *githubOwner,
		GitHubRepo:                *githubRepo,
		GitHubToken:               *githubToken,
		GitHubWorkflowFile:        *githubWorkflowFile,
		GitHubWorkflowRef:         *githubWorkflowRef,
		JiraBaseURL:               *jiraBaseURL,
		JiraEmail:                 *jiraEmail,
		JiraAPIToken:              *jiraAPIToken,
		JiraProjectKey:            *jiraProjectKey,
		JiraIssueType:             *jiraIssueType,
		ServiceNowInstanceURL:     *servicenowURL,
		ServiceNowUser:            *servicenowUser,
		ServiceNowPassword:        *servicenowPassword,
		MCPUpstreamURL:            *mcpUpstreamURL,
		MCPUpstreamToken:          *mcpUpstreamToken,
		ProxyAllowLocalTargets:    *proxyAllowLocalTargets,
		OIDCIssuerURL:             *oidcIssuerURL,
		OIDCClientID:              *oidcClientID,
		OIDCClientSecret:          *oidcClientSecret,
		OIDCRedirectURL:           *oidcRedirectURL,
		OIDCScopes:                splitCSV(*oidcScopes),
		OIDCTenantClaim:           *oidcTenantClaim,
		OIDCRoleClaim:             *oidcRoleClaim,
		OIDCEmailClaim:            *oidcEmailClaim,
		SAMLRootURL:               *samlRootURL,
		SAMLIDPMetadataURL:        *samlIDPMetadataURL,
		SAMLKeyPath:               *samlKeyPath,
		SAMLCertPath:              *samlCertPath,
		SAMLTenantAttribute:       *samlTenantAttribute,
		SAMLRoleAttribute:         *samlRoleAttribute,
		SAMLEmailAttribute:        *samlEmailAttribute,
		PublicURL:                 *publicURL,
		InstanceName:              *instanceName,
		TenantIsolationMode:       *tenantIsolationMode,
		TenantRegistryPath:        *tenantRegistryPath,
		TenantPostgresDSNTemplate: *tenantPostgresDSNTemplate,
		TenantDataPathTemplate:    *tenantDataPathTemplate,
		TrustedProxies:            splitCSV(*trustedProxies),
		RetentionWindow:           retention,
		GatewayMaxInFlight:        *gatewayMaxInFlight,
	})
	if err != nil {
		log.Fatal(err)
	}
	if *withDemo {
		alerts, err := app.LoadDemo()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("loaded demo telemetry with %d initial alerts", len(alerts))
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	actualAddr := listener.Addr().String()
	log.Printf("Open Agentic Threat Defense %s listening on http://%s", server.Version, actualAddr)
	srv := &http.Server{
		Addr:              actualAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	go func() {
		for range reload {
			if rules, err := app.ReloadPolicy(); err != nil {
				log.Printf("policy reload failed: %v", err)
			} else {
				log.Printf("policy reloaded: %d rules active", rules)
			}
		}
	}()

	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	return values
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func defaultIntEnv(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseFlexibleDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("duration is empty")
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, nil
	}

	type unit struct {
		suffix     string
		multiplier time.Duration
	}
	for _, candidate := range []unit{
		{suffix: "w", multiplier: 7 * 24 * time.Hour},
		{suffix: "d", multiplier: 24 * time.Hour},
	} {
		if !strings.HasSuffix(value, candidate.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(value, candidate.suffix))
		if number == "" {
			return 0, errors.New("duration is empty")
		}
		amount, err := strconv.ParseFloat(number, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(amount * float64(candidate.multiplier)), nil
	}

	return 0, errors.New("invalid duration")
}
