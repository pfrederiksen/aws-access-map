package types

import "time"

// Principal represents an AWS principal (user, role, group, service)
type Principal struct {
	ARN         string
	Type        PrincipalType
	Name        string
	AccountID   string
	Policies    []PolicyDocument
	TrustPolicy *PolicyDocument
}

// PrincipalType represents the type of principal
type PrincipalType string

const (
	PrincipalTypeUser    PrincipalType = "user"
	PrincipalTypeRole    PrincipalType = "role"
	PrincipalTypeGroup   PrincipalType = "group"
	PrincipalTypeService PrincipalType = "service"
	PrincipalTypePublic  PrincipalType = "public"
)

// Resource represents an AWS resource (S3 bucket, KMS key, etc.)
type Resource struct {
	ARN           string
	Type          ResourceType
	Name          string
	Region        string
	AccountID     string
	ResourcePolicy *PolicyDocument
}

// ResourceType represents the type of resource
type ResourceType string

const (
	ResourceTypeS3            ResourceType = "s3"
	ResourceTypeKMS           ResourceType = "kms"
	ResourceTypeSQS           ResourceType = "sqs"
	ResourceTypeSNS           ResourceType = "sns"
	ResourceTypeSecretsManager ResourceType = "secretsmanager"
	ResourceTypeLambda        ResourceType = "lambda"
)

// PolicyDocument represents an AWS IAM policy document
type PolicyDocument struct {
	Version    string      `json:"Version"`
	ID         string      `json:"Id,omitempty"`
	Statements []Statement `json:"Statement"`
}

// Statement represents a single statement in a policy document
type Statement struct {
	Sid       string                              `json:"Sid,omitempty"`
	Effect    Effect                              `json:"Effect"`
	Principal interface{}                         `json:"Principal,omitempty"` // Can be string, []string, or map[string]interface{}
	Action    interface{}                         `json:"Action,omitempty"`    // Can be string or []string
	Resource  interface{}                         `json:"Resource,omitempty"`  // Can be string or []string
	Condition map[string]map[string]interface{} `json:"Condition,omitempty"`
}

// Effect represents Allow or Deny
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// AccessPath represents a path from a principal to a resource
type AccessPath struct {
	From       *Principal
	To         *Resource
	Action     string
	Hops       []AccessHop
	Conditions []string // Human-readable conditions that must be met
}

// AccessHop represents a single hop in an access path
type AccessHop struct {
	From        *Principal
	To          interface{} // Can be Principal or Resource
	Action      string
	PolicyType  PolicyType
	PolicyName  string
	Conditions  []string
}

// PolicyType represents the type of policy that grants access
type PolicyType string

const (
	PolicyTypeIdentity    PolicyType = "identity"
	PolicyTypeResource    PolicyType = "resource"
	PolicyTypeTrust       PolicyType = "trust"
	PolicyTypeSCP         PolicyType = "scp"
	PolicyTypeBoundary    PolicyType = "boundary"
)

// CollectionResult holds all collected AWS data
type CollectionResult struct {
	Principals  []*Principal
	Resources   []*Resource
	SCPs        []PolicyDocument
	CollectedAt time.Time
	AccountID   string
	Regions     []string
}
