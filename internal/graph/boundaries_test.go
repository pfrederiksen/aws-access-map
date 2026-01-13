package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestIsBlockedByBoundary_ExplicitAllow tests boundary allows action when explicitly permitted
func TestIsBlockedByBoundary_ExplicitAllow(t *testing.T) {
	g := New()

	// User with boundary that allows S3 actions
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
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-allow-s3",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(principal)
	ctx := conditions.NewDefaultContext()

	// S3 action should be allowed by boundary
	if g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected boundary to allow s3:GetObject")
	}
}

// TestIsBlockedByBoundary_ImplicitDeny tests boundary blocks action when not explicitly allowed
func TestIsBlockedByBoundary_ImplicitDeny(t *testing.T) {
	g := New()

	// User with boundary that only allows S3 actions
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
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-allow-s3-only",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(principal)
	ctx := conditions.NewDefaultContext()

	// IAM action should be blocked by boundary (implicit deny)
	if !g.isBlockedByBoundary(principal.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected boundary to block iam:CreateUser via implicit deny")
	}

	// S3 action should still be allowed
	if g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected boundary to allow s3:GetObject")
	}
}

// TestIsBlockedByBoundary_NoBoundary tests that no boundary means nothing is blocked
func TestIsBlockedByBoundary_NoBoundary(t *testing.T) {
	g := New()

	// User without a permission boundary
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
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
		PermissionsBoundary: nil, // No boundary
	}

	g.AddPrincipal(principal)
	ctx := conditions.NewDefaultContext()

	// No boundary means nothing is blocked
	if g.isBlockedByBoundary(principal.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected no boundary to not block any action")
	}
}

// TestIsBlockedByBoundary_WildcardMatching tests wildcard pattern matching in boundaries
func TestIsBlockedByBoundary_WildcardMatching(t *testing.T) {
	g := New()

	// User with boundary using wildcard patterns
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
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-wildcards",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:Get*", // Wildcard in action
					Resource: "arn:aws:s3:::my-bucket/*", // Wildcard in resource
				},
			},
		},
	}

	g.AddPrincipal(principal)
	ctx := conditions.NewDefaultContext()

	// s3:GetObject should match s3:Get* wildcard
	if g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected s3:Get* to match s3:GetObject")
	}

	// s3:PutObject should NOT match s3:Get* wildcard
	if !g.isBlockedByBoundary(principal.ARN, "s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected s3:Get* to NOT match s3:PutObject")
	}

	// Resource outside bucket should be blocked
	if !g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::other-bucket/file.txt", ctx) {
		t.Error("Expected boundary to block access to other-bucket")
	}
}

// TestIsBlockedByBoundary_ExplicitDeny tests that explicit deny in boundary blocks action
func TestIsBlockedByBoundary_ExplicitDeny(t *testing.T) {
	g := New()

	// User with boundary that allows all but explicitly denies IAM
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
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-deny-iam",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
				{
					Effect:   types.EffectDeny,
					Action:   "iam:*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(principal)
	ctx := conditions.NewDefaultContext()

	// IAM action should be blocked by explicit deny
	if !g.isBlockedByBoundary(principal.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected boundary explicit deny to block iam:CreateUser")
	}

	// S3 action should still be allowed (allow without deny)
	if g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected boundary to allow s3:GetObject")
	}
}

// TestIsBlockedByBoundary_Conditions tests condition evaluation in boundaries
func TestIsBlockedByBoundary_Conditions(t *testing.T) {
	g := New()

	// User with boundary that has IP condition
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
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-ip-restricted",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:*",
					Resource: "*",
					Condition: map[string]map[string]interface{}{
						"IpAddress": {
							"aws:SourceIp": "203.0.113.0/24", // Office IP range
						},
					},
				},
			},
		},
	}

	g.AddPrincipal(principal)

	// From office IP - should be allowed
	officeCtx := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", officeCtx) {
		t.Error("Expected boundary to allow from office IP")
	}

	// From home IP - should be blocked (condition doesn't match)
	homeCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if !g.isBlockedByBoundary(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", homeCtx) {
		t.Error("Expected boundary to block from home IP (condition mismatch)")
	}
}

// TestCanAccess_BoundaryAndIdentityPolicy tests integration with CanAccess
func TestCanAccess_BoundaryAndIdentityPolicy(t *testing.T) {
	g := New()

	// User with full S3 access but boundary that only allows Get operations
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
						Action:   "s3:*",
						Resource: "*",
					},
				},
			},
		},
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-readonly-s3",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:Get*",
					Resource: "*",
				},
				{
					Effect:   types.EffectAllow,
					Action:   "s3:List*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(principal)

	// Process identity policies
	for _, policy := range principal.Policies {
		err := g.addPolicyEdges(principal.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	ctx := conditions.NewDefaultContext()

	// Get operations allowed (both identity policy and boundary allow)
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected CanAccess to allow s3:GetObject (both policies allow)")
	}

	// Put operations blocked by boundary (identity allows but boundary doesn't)
	if g.CanAccess(principal.ARN, "s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected CanAccess to block s3:PutObject (boundary implicit deny)")
	}
}

// TestCanAccess_BoundaryBlocksAdminAccess tests real-world scenario: admin with PowerUserAccess boundary
func TestCanAccess_BoundaryBlocksAdminAccess(t *testing.T) {
	g := New()

	// User with AdministratorAccess policy but PowerUserAccess boundary
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
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "PowerUserAccess",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
				{
					Effect:   types.EffectDeny,
					Action:   "iam:*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(principal)

	// Process identity policies
	for _, policy := range principal.Policies {
		err := g.addPolicyEdges(principal.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	ctx := conditions.NewDefaultContext()

	// S3 operations allowed (both identity policy and boundary allow)
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected admin to have S3 access with PowerUserAccess boundary")
	}

	// IAM operations blocked by boundary deny (even though identity policy allows)
	if g.CanAccess(principal.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected PowerUserAccess boundary to block IAM operations")
	}

	// EC2 operations allowed
	if !g.CanAccess(principal.ARN, "ec2:DescribeInstances", "*", ctx) {
		t.Error("Expected admin to have EC2 access with PowerUserAccess boundary")
	}
}
