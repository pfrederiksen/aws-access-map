package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestIsBlockedBySCP_ExplicitDeny tests SCP explicitly denying an action
func TestIsBlockedBySCP_ExplicitDeny(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-s3-delete",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "s3:DeleteBucket",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Should be blocked
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to block s3:DeleteBucket")
	}

	// Should NOT be blocked (different action)
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to NOT block s3:GetObject")
	}
}

// TestIsBlockedBySCP_WildcardDeny tests SCP with wildcard action deny
func TestIsBlockedBySCP_WildcardDeny(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-all-s3",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "s3:*",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Should block all S3 actions
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to block s3:DeleteBucket with wildcard")
	}

	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected SCP to block s3:GetObject with wildcard")
	}

	// Should NOT block non-S3 actions
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "iam:CreateUser", "*", ctx) {
		t.Error("Expected SCP to NOT block iam:CreateUser")
	}
}

// TestIsBlockedBySCP_NoSCPs tests that empty SCP list doesn't block anything
func TestIsBlockedBySCP_NoSCPs(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{}

	ctx := conditions.NewDefaultContext()

	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected no SCPs to not block any action")
	}
}

// TestIsBlockedBySCP_RootUser tests that root user bypasses SCPs
func TestIsBlockedBySCP_RootUser(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-all",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "*",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Root user should bypass SCP
	if g.isBlockedBySCP("arn:aws:iam::123456789012:root", "*", "*", ctx) {
		t.Error("Expected root user to bypass SCP")
	}

	// Regular user should be blocked
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "*", "*", ctx) {
		t.Error("Expected regular user to be blocked by SCP")
	}
}

// TestIsBlockedBySCP_Conditions tests SCP with condition evaluation
func TestIsBlockedBySCP_Conditions(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-from-home",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "*",
					Resource: "*",
					Condition: map[string]map[string]interface{}{
						"NotIpAddress": {
							"aws:SourceIp": "203.0.113.0/24", // Office IP range
						},
					},
				},
			},
		},
	}

	// From office IP - should NOT be blocked
	officeCtx := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::bucket/file.txt", officeCtx) {
		t.Error("Expected office IP to NOT be blocked")
	}

	// From home IP - should be blocked
	homeCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::bucket/file.txt", homeCtx) {
		t.Error("Expected home IP to be blocked")
	}
}

// TestIsBlockedBySCP_AllowStatementIgnored tests that Allow statements in SCPs are ignored
func TestIsBlockedBySCP_AllowStatementIgnored(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-with-allow",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow, // Allow in SCP doesn't grant access
					Action:   "s3:*",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Allow statement should be ignored, nothing is blocked
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected Allow statement in SCP to be ignored (not block)")
	}
}

// TestCanAccess_BlockedBySCP tests integration with CanAccess
func TestCanAccess_BlockedBySCP(t *testing.T) {
	g := New()

	// Add a principal with full S3 access
	principal := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:*",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(principal)

	// Process principal's policies
	for _, policy := range principal.Policies {
		err := g.addPolicyEdges(principal.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	ctx := conditions.NewDefaultContext()

	// Without SCP, admin can delete buckets
	if !g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected admin to have access without SCP")
	}

	// Add SCP that denies bucket deletion
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-bucket-delete",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "s3:DeleteBucket",
					Resource: "*",
				},
			},
		},
	}

	// With SCP, admin CANNOT delete buckets (SCP denies)
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to block admin from deleting buckets")
	}

	// Admin can still perform other S3 actions
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected admin to still have GetObject access")
	}
}

// TestCanAccess_MultipleSCPs tests multiple SCPs with different denies
func TestCanAccess_MultipleSCPs(t *testing.T) {
	g := New()

	principal := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(principal)

	for _, policy := range principal.Policies {
		err := g.addPolicyEdges(principal.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	// Add multiple SCPs
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-iam",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "iam:*",
					Resource: "*",
				},
			},
		},
		{
			ID:      "scp-deny-s3-delete",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "s3:DeleteBucket",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Blocked by first SCP
	if g.CanAccess(principal.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected first SCP to block IAM actions")
	}

	// Blocked by second SCP
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected second SCP to block S3 bucket deletion")
	}

	// Not blocked by any SCP
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected S3 GetObject to NOT be blocked")
	}
}

// TestIsRootUser tests the root user detection
func TestIsRootUser(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want bool
	}{
		{
			name: "Root user ARN",
			arn:  "arn:aws:iam::123456789012:root",
			want: true,
		},
		{
			name: "Root user ARN with slash",
			arn:  "arn:aws:iam::123456789012:root/",
			want: true,
		},
		{
			name: "Regular user",
			arn:  "arn:aws:iam::123456789012:user/alice",
			want: false,
		},
		{
			name: "Role ARN",
			arn:  "arn:aws:iam::123456789012:role/MyRole",
			want: false,
		},
		{
			name: "Empty ARN",
			arn:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRootUser(tt.arn)
			if got != tt.want {
				t.Errorf("isRootUser(%q) = %v, want %v", tt.arn, got, tt.want)
			}
		})
	}
}

// TestCanAccess_SCPResourcePattern tests SCP with specific resource patterns
func TestCanAccess_SCPResourcePattern(t *testing.T) {
	g := New()

	principal := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:*",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(principal)

	for _, policy := range principal.Policies {
		err := g.addPolicyEdges(principal.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	// SCP denies access only to production buckets
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-protect-prod",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectDeny,
					Action:   "s3:DeleteBucket",
					Resource: "arn:aws:s3:::prod-*", // Only production buckets
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Blocked for production bucket
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::prod-data", ctx) {
		t.Error("Expected SCP to block deletion of production bucket")
	}

	// NOT blocked for dev bucket
	if !g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::dev-data", ctx) {
		t.Error("Expected dev bucket deletion to be allowed")
	}
}
