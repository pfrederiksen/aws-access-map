package output

import "time"

// WhoCanOutput represents JSON output for who-can command
type WhoCanOutput struct {
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	Principals []PrincipalOutput `json:"principals"`
}

// PathsOutput represents JSON output for path command
type PathsOutput struct {
	From   string       `json:"from"`
	To     string       `json:"to"`
	Action string       `json:"action"`
	Paths  []PathOutput `json:"paths"`
}

// PathOutput represents a single access path
type PathOutput struct {
	Hops       []HopOutput `json:"hops"`
	Conditions []string    `json:"conditions,omitempty"`
}

// HopOutput represents a single hop in an access path
type HopOutput struct {
	From       PrincipalOutput `json:"from"`
	To         interface{}     `json:"to"` // Can be PrincipalOutput or ResourceOutput
	Action     string          `json:"action"`
	PolicyType string          `json:"policy_type"`
}

// ReportOutput represents JSON output for report command
type ReportOutput struct {
	AccountID   string          `json:"account_id"`
	GeneratedAt string          `json:"generated_at"`
	Findings    []FindingOutput `json:"findings"`
}

// FindingOutput represents a single security finding
type FindingOutput struct {
	Type        string           `json:"type"`
	Severity    string           `json:"severity"`
	Description string           `json:"description"`
	Principal   *PrincipalOutput `json:"principal,omitempty"`
	Resource    *ResourceOutput  `json:"resource,omitempty"`
	Action      string           `json:"action,omitempty"`
}

// PrincipalOutput represents a principal in JSON output
type PrincipalOutput struct {
	ARN       string `json:"arn"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	AccountID string `json:"account_id,omitempty"`
}

// ResourceOutput represents a resource in JSON output
type ResourceOutput struct {
	ARN       string `json:"arn"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Region    string `json:"region,omitempty"`
	AccountID string `json:"account_id,omitempty"`
}

// CollectOutput represents JSON output for collect command
type CollectOutput struct {
	AccountID      string            `json:"account_id"`
	Regions        []string          `json:"regions"`
	CollectedAt    time.Time         `json:"collected_at"`
	PrincipalCount int               `json:"principal_count"`
	ResourceCount  int               `json:"resource_count"`
	Principals     []PrincipalOutput `json:"principals,omitempty"`
	Resources      []ResourceOutput  `json:"resources,omitempty"`
}
