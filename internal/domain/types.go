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
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Mode      string            `json:"mode"`
	AssetID   string            `json:"asset_id"`
	Target    string            `json:"target"`
	Reason    string            `json:"reason"`
	CreatedAt time.Time         `json:"created_at"`
	Metadata  map[string]string `json:"metadata"`
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
	StartedAt        time.Time `json:"started_at"`
	StorageMode      string    `json:"storage_mode"`
	StoragePath      string    `json:"storage_path,omitempty"`
	LastStorageError string    `json:"last_storage_error,omitempty"`
}
