package domain

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

type EventKind string

const (
	EventHostObservation EventKind = "host_observation"
	EventNetworkFlow     EventKind = "network_flow"
	EventProcessStart    EventKind = "process_start"
	EventAgentToolCall   EventKind = "agent_tool_call"
	EventAuth            EventKind = "auth"
	EventDeceptionHit    EventKind = "deception_hit"
	EventFinding         EventKind = "finding"
)

type Event struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Kind        EventKind         `json:"kind"`
	AssetID     string            `json:"asset_id"`
	Hostname    string            `json:"hostname"`
	Actor       string            `json:"actor"`
	SourceIP    string            `json:"source_ip"`
	Destination string            `json:"destination"`
	Process     string            `json:"process"`
	ToolName    string            `json:"tool_name"`
	Command     string            `json:"command"`
	Signal      string            `json:"signal"`
	Labels      []string          `json:"labels"`
	Metadata    map[string]string `json:"metadata"`
}

type ToolCallRequest struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	AssetID     string            `json:"asset_id"`
	Hostname    string            `json:"hostname"`
	Actor       string            `json:"actor"`
	ToolName    string            `json:"tool_name"`
	Command     string            `json:"command,omitempty"`
	Arguments   string            `json:"arguments,omitempty"`
	Signal      string            `json:"signal,omitempty"`
	Destination string            `json:"destination,omitempty"`
	Labels      []string          `json:"labels,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type GatewayVerdict string

const (
	GatewayAllow           GatewayVerdict = "allow"
	GatewayDeny            GatewayVerdict = "deny"
	GatewayRequireApproval GatewayVerdict = "require_approval"
)

type ToolCallDecision struct {
	ID                 string            `json:"id"`
	RequestID          string            `json:"request_id"`
	ToolName           string            `json:"tool_name"`
	Verdict            GatewayVerdict    `json:"verdict"`
	Reason             string            `json:"reason"`
	Risk               Severity          `json:"risk"`
	CreatedAt          time.Time         `json:"created_at"`
	Action             *ResponseAction   `json:"action,omitempty"`
	Alerts             []Alert           `json:"alerts,omitempty"`
	RecommendedActions []ResponseAction  `json:"recommended_actions,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type ToolExecutionResult struct {
	Decision ToolCallDecision `json:"decision"`
	Status   string           `json:"status"`
	Result   string           `json:"result,omitempty"`
	Action   *ResponseAction  `json:"action,omitempty"`
}

type AlertStatus string

const (
	AlertOpen     AlertStatus = "open"
	AlertResolved AlertStatus = "resolved"
)

type Alert struct {
	ID                 string            `json:"id"`
	Fingerprint        string            `json:"fingerprint"`
	RuleID             string            `json:"rule_id"`
	Title              string            `json:"title"`
	Description        string            `json:"description"`
	Severity           Severity          `json:"severity"`
	Status             AlertStatus       `json:"status"`
	AssetID            string            `json:"asset_id"`
	CreatedAt          time.Time         `json:"created_at"`
	EventIDs           []string          `json:"event_ids"`
	Evidence           map[string]string `json:"evidence"`
	RecommendedActions []ResponseAction  `json:"recommended_actions"`
}

type ResponseAction struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	Mode            string            `json:"mode"`
	AssetID         string            `json:"asset_id"`
	Target          string            `json:"target"`
	Reason          string            `json:"reason"`
	CreatedAt       time.Time         `json:"created_at"`
	ApprovalStatus  string            `json:"approval_status,omitempty"`
	ApprovedBy      string            `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time        `json:"approved_at,omitempty"`
	ExecutionStatus string            `json:"execution_status,omitempty"`
	ExecutedAt      *time.Time        `json:"executed_at,omitempty"`
	ExecutionError  string            `json:"execution_error,omitempty"`
	Metadata        map[string]string `json:"metadata"`
}

type Asset struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	IPs          []string          `json:"ips"`
	AgentSurface []string          `json:"agent_surface"`
	RiskScore    int               `json:"risk_score"`
	LastSeen     time.Time         `json:"last_seen"`
	Labels       []string          `json:"labels"`
	Metadata     map[string]string `json:"metadata"`
}

type AuditEvent struct {
	ID           string            `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	Actor        string            `json:"actor"`
	Roles        []string          `json:"roles"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id,omitempty"`
	Outcome      string            `json:"outcome"`
	SourceIP     string            `json:"source_ip,omitempty"`
	UserAgent    string            `json:"user_agent,omitempty"`
	Metadata     map[string]string `json:"metadata"`
}

type RuleDescriptor struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Signals     []string `json:"signals"`
}

type Status struct {
	Version          string    `json:"version"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
	EventCount       int       `json:"event_count"`
	AlertCount       int       `json:"alert_count"`
	AssetCount       int       `json:"asset_count"`
	ActionCount      int       `json:"action_count"`
	AuditCount       int       `json:"audit_count"`
	StartedAt        time.Time `json:"started_at"`
	StorageMode      string    `json:"storage_mode"`
	StoragePath      string    `json:"storage_path,omitempty"`
	SchemaVersion    int       `json:"schema_version,omitempty"`
	LastStorageError string    `json:"last_storage_error,omitempty"`
	LastExportError  string    `json:"last_export_error,omitempty"`
}
