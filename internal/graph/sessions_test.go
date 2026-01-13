package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestIsBlockedBySessionPolicy_ExplicitAllow tests session policy allows action when explicitly permitted
func TestIsBlockedBySessionPolicy_ExplicitAllow(t *testing.T) {
	g := New()

	// Session policy that allows S3 read actions
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-readonly-s3",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "s3:Get*",
				Resource: "*",
			},
		},
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// S3 Get action should be allowed by session policy
	if g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected session policy to allow s3:GetObject")
	}
}

// TestIsBlockedBySessionPolicy_ImplicitDeny tests session policy blocks action when not explicitly allowed
func TestIsBlockedBySessionPolicy_ImplicitDeny(t *testing.T) {
	g := New()

	// Session policy that only allows S3 read actions
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-readonly-s3",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "s3:Get*",
				Resource: "*",
			},
		},
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// S3 Put action should be blocked by session policy (implicit deny)
	if !g.isBlockedBySessionPolicy("s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected session policy to block s3:PutObject via implicit deny")
	}

	// S3 Get action should still be allowed
	if g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected session policy to allow s3:GetObject")
	}
}

// TestIsBlockedBySessionPolicy_NoSession tests that no session policy means nothing is blocked
func TestIsBlockedBySessionPolicy_NoSession(t *testing.T) {
	g := New()

	// Context without a session policy
	ctx := conditions.NewDefaultContext()

	// No session policy means nothing is blocked
	if g.isBlockedBySessionPolicy("iam:CreateUser", "*", ctx) {
		t.Error("Expected no session policy to not block any action")
	}

	// Also test with nil context
	if g.isBlockedBySessionPolicy("iam:CreateUser", "*", nil) {
		t.Error("Expected nil context to not block any action")
	}
}

// TestIsBlockedBySessionPolicy_WildcardMatching tests wildcard pattern matching in session policies
func TestIsBlockedBySessionPolicy_WildcardMatching(t *testing.T) {
	g := New()

	// Session policy using wildcard patterns
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-wildcards",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "s3:Get*", // Wildcard in action
				Resource: "arn:aws:s3:::my-bucket/*", // Wildcard in resource
			},
		},
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// s3:GetObject should match s3:Get* wildcard
	if g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected s3:Get* to match s3:GetObject")
	}

	// s3:PutObject should NOT match s3:Get* wildcard
	if !g.isBlockedBySessionPolicy("s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected s3:Get* to NOT match s3:PutObject")
	}

	// Resource outside bucket should be blocked
	if !g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::other-bucket/file.txt", ctx) {
		t.Error("Expected session policy to block access to other-bucket")
	}
}

// TestIsBlockedBySessionPolicy_ExplicitDeny tests that explicit deny in session policy blocks action
func TestIsBlockedBySessionPolicy_ExplicitDeny(t *testing.T) {
	g := New()

	// Session policy that allows all but explicitly denies IAM
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-deny-iam",
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
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// IAM action should be blocked by explicit deny
	if !g.isBlockedBySessionPolicy("iam:CreateUser", "*", ctx) {
		t.Error("Expected session policy explicit deny to block iam:CreateUser")
	}

	// S3 action should still be allowed (allow without deny)
	if g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected session policy to allow s3:GetObject")
	}
}

// TestIsBlockedBySessionPolicy_Conditions tests condition evaluation in session policies
func TestIsBlockedBySessionPolicy_Conditions(t *testing.T) {
	g := New()

	// Session policy that has IP condition
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-ip-restricted",
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
	}

	// From office IP - should be allowed
	officeCtx := &conditions.EvaluationContext{
		SourceIP:      "203.0.113.50",
		SessionPolicy: sessionPolicy,
	}
	if g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket", officeCtx) {
		t.Error("Expected session policy to allow from office IP")
	}

	// From home IP - should be blocked (condition doesn't match)
	homeCtx := &conditions.EvaluationContext{
		SourceIP:      "192.0.2.1",
		SessionPolicy: sessionPolicy,
	}
	if !g.isBlockedBySessionPolicy("s3:GetObject", "arn:aws:s3:::my-bucket", homeCtx) {
		t.Error("Expected session policy to block from home IP (condition mismatch)")
	}
}

// TestCanAccess_SessionPolicyNarrows tests that session policy narrows role permissions
func TestCanAccess_SessionPolicyNarrows(t *testing.T) {
	g := New()

	// Role with full S3 access
	role := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/AdminRole",
		Type: types.PrincipalTypeRole,
		Name: "AdminRole",
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

	g.AddPrincipal(role)

	// Process identity policies
	for _, policy := range role.Policies {
		err := g.addPolicyEdges(role.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	// Without session policy - full S3 access
	ctxNoSession := conditions.NewDefaultContext()
	if !g.CanAccess(role.ARN, "s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctxNoSession) {
		t.Error("Expected role to have s3:PutObject access without session policy")
	}

	// With session policy that only allows Get operations
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-readonly",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "s3:Get*",
				Resource: "*",
			},
		},
	}

	ctxWithSession := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// Get operations allowed (both identity policy and session policy allow)
	if !g.CanAccess(role.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctxWithSession) {
		t.Error("Expected CanAccess to allow s3:GetObject (both policies allow)")
	}

	// Put operations blocked by session policy (identity allows but session doesn't)
	if g.CanAccess(role.ARN, "s3:PutObject", "arn:aws:s3:::my-bucket/file.txt", ctxWithSession) {
		t.Error("Expected CanAccess to block s3:PutObject (session policy implicit deny)")
	}
}

// TestCanAccess_SessionPolicyWithBoundary tests session policy works together with permission boundary
func TestCanAccess_SessionPolicyWithBoundary(t *testing.T) {
	g := New()

	// User with full access but has permission boundary and session policy
	user := &types.Principal{
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
		// Permission boundary allows S3 and DynamoDB
		PermissionsBoundary: &types.PolicyDocument{
			ID:      "boundary-s3-dynamodb",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:*",
					Resource: "*",
				},
				{
					Effect:   types.EffectAllow,
					Action:   "dynamodb:*",
					Resource: "*",
				},
			},
		},
	}

	g.AddPrincipal(user)

	// Process identity policies
	for _, policy := range user.Policies {
		err := g.addPolicyEdges(user.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	// Session policy only allows S3 read and DynamoDB write
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-mixed",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "s3:Get*",
				Resource: "*",
			},
			{
				Effect:   types.EffectAllow,
				Action:   "dynamodb:Put*",
				Resource: "*",
			},
		},
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// S3 read: allowed by all three (identity, boundary, session)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::bucket", ctx) {
		t.Error("Expected s3:GetObject to be allowed (all three allow)")
	}

	// S3 write: blocked by session policy (identity and boundary allow, but session doesn't)
	if g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::bucket", ctx) {
		t.Error("Expected s3:PutObject to be blocked by session policy")
	}

	// DynamoDB write: allowed by all three
	if !g.CanAccess(user.ARN, "dynamodb:PutItem", "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable", ctx) {
		t.Error("Expected dynamodb:PutItem to be allowed (all three allow)")
	}

	// DynamoDB read: blocked by session policy (identity and boundary allow, but session doesn't)
	if g.CanAccess(user.ARN, "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable", ctx) {
		t.Error("Expected dynamodb:GetItem to be blocked by session policy")
	}

	// IAM: blocked by permission boundary (identity and session allow, but boundary doesn't)
	if g.CanAccess(user.ARN, "iam:CreateUser", "*", ctx) {
		t.Error("Expected iam:CreateUser to be blocked by permission boundary")
	}
}

// TestCanAccess_SessionPolicyDenyOverridesAllow tests that explicit deny in session policy takes precedence
func TestCanAccess_SessionPolicyDenyOverridesAllow(t *testing.T) {
	g := New()

	// Role with full access
	role := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/PowerUser",
		Type: types.PrincipalTypeRole,
		Name: "PowerUser",
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

	g.AddPrincipal(role)

	// Process identity policies
	for _, policy := range role.Policies {
		err := g.addPolicyEdges(role.ARN, policy)
		if err != nil {
			t.Fatalf("Failed to add policy edges: %v", err)
		}
	}

	// Session policy allows all but denies delete operations
	sessionPolicy := &types.PolicyDocument{
		ID:      "session-no-delete",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   "*",
				Resource: "*",
			},
			{
				Effect:   types.EffectDeny,
				Action:   "*:Delete*",
				Resource: "*",
			},
		},
	}

	ctx := &conditions.EvaluationContext{
		SessionPolicy: sessionPolicy,
	}

	// Read operations allowed
	if !g.CanAccess(role.ARN, "s3:GetObject", "arn:aws:s3:::bucket", ctx) {
		t.Error("Expected s3:GetObject to be allowed")
	}

	// Delete operations blocked by explicit deny in session policy
	if g.CanAccess(role.ARN, "s3:DeleteObject", "arn:aws:s3:::bucket/file.txt", ctx) {
		t.Error("Expected s3:DeleteObject to be blocked by session policy deny")
	}

	if g.CanAccess(role.ARN, "ec2:DeleteVolume", "*", ctx) {
		t.Error("Expected ec2:DeleteVolume to be blocked by session policy deny")
	}
}
