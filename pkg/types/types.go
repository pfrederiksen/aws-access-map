package types

import "time"

// Principal represents an AWS principal (user, role, group, service)
type Principal struct {
	ARN                 string
	Type                PrincipalType
	Name                string
	AccountID           string
	Policies            []PolicyDocument
	TrustPolicy         *PolicyDocument
	PermissionsBoundary *PolicyDocument
	GroupMemberships    []string // Group ARNs this principal belongs to (for users)
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
	ResourceTypeAPIGateway    ResourceType = "apigateway"
	ResourceTypeECR           ResourceType = "ecr"
	ResourceTypeEventBridge   ResourceType = "eventbridge"
)

// PolicyDocument represents an AWS IAM policy document
type PolicyDocument struct {
	Version    string      `json:"Version"`
	ID         string      `json:"Id,omitempty"`
	Statements []Statement `json:"Statement"`
}

// Statement represents a single statement in a policy document
type Statement struct {
	Sid         string                              `json:"Sid,omitempty"`
	Effect      Effect                              `json:"Effect"`
	Principal   interface{}                         `json:"Principal,omitempty"`   // Can be string, []string, or map[string]interface{}
	Action      interface{}                         `json:"Action,omitempty"`      // Can be string or []string
	NotAction   interface{}                         `json:"NotAction,omitempty"`   // Can be string or []string - inverse of Action
	Resource    interface{}                         `json:"Resource,omitempty"`    // Can be string or []string
	NotResource interface{}                         `json:"NotResource,omitempty"` // Can be string or []string - inverse of Resource
	Condition   map[string]map[string]interface{} `json:"Condition,omitempty"`
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

// SCPAttachment represents a Service Control Policy and its targets
type SCPAttachment struct {
	Policy  PolicyDocument
	Targets []SCPTarget
}

// SCPTarget represents a target (account, OU, or root) where an SCP is attached
type SCPTarget struct {
	Type       SCPTargetType
	ID         string // Account ID, OU ID, or "ROOT"
	ARN        string `json:"Arn,omitempty"`
	Name       string `json:"Name,omitempty"`
}

// SCPTargetType represents the type of SCP target
type SCPTargetType string

const (
	SCPTargetTypeAccount        SCPTargetType = "ACCOUNT"
	SCPTargetTypeOrganizationalUnit SCPTargetType = "ORGANIZATIONAL_UNIT"
	SCPTargetTypeRoot           SCPTargetType = "ROOT"
)

// OUHierarchy represents the organizational unit hierarchy for an account
type OUHierarchy struct {
	AccountID string
	ParentOUs []string // List of OU IDs from immediate parent to root
}

// CollectionResult holds all collected AWS data for a single account
type CollectionResult struct {
	Principals      []*Principal
	Resources       []*Resource
	SCPs            []PolicyDocument    // Deprecated: Use SCPAttachments for hierarchy-aware filtering
	SCPAttachments  []SCPAttachment     // SCPs with target information
	OUHierarchy     *OUHierarchy        // OU membership for the account
	CollectedAt     time.Time
	AccountID       string
	Regions         []string
}

// MultiAccountCollectionResult holds collected AWS data from multiple accounts
type MultiAccountCollectionResult struct {
	Accounts       map[string]*CollectionResult // AccountID -> CollectionResult
	SCPAttachments []SCPAttachment              // Organization-wide SCPs
	OUHierarchy    map[string]*OUHierarchy      // AccountID -> OU hierarchy
	CollectedAt    time.Time
	OrganizationID string
	SuccessCount   int      // Number of accounts successfully collected
	FailureCount   int      // Number of accounts that failed
	FailedAccounts []string // Account IDs that failed collection
}
