package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestCanAccessWithConditions_IPRestriction(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/alice"
	resourceARN := "arn:aws:s3:::bucket/*"
	action := "s3:GetObject"

	// Add edge with IP restriction condition
	ipCondition := map[string]map[string]interface{}{
		"IpAddress": {
			"aws:SourceIp": "203.0.113.0/24",
		},
	}
	g.AddEdgeWithConditions(principalARN, action, resourceARN, false, ipCondition, "AllowFromOfficeIP")

	// Test 1: Access from allowed IP - should pass
	ctxAllowed := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if !g.CanAccess(principalARN, action, resourceARN, ctxAllowed) {
		t.Error("Should allow access from IP within CIDR block")
	}

	// Test 2: Access from denied IP - should fail
	ctxDenied := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxDenied) {
		t.Error("Should deny access from IP outside CIDR block")
	}

	// Test 3: No context (default permissive) - should pass
	if !g.CanAccess(principalARN, action, resourceARN) {
		t.Error("Should allow access with default permissive context")
	}
}

func TestCanAccessWithConditions_MFARequired(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/admin"
	resourceARN := "*"
	action := "*"

	// Add edge with MFA requirement
	mfaCondition := map[string]map[string]interface{}{
		"Bool": {
			"aws:MultiFactorAuthPresent": true,
		},
	}
	g.AddEdgeWithConditions(principalARN, action, resourceARN, false, mfaCondition, "RequireMFA")

	// Test 1: Access with MFA - should pass
	ctxWithMFA := &conditions.EvaluationContext{
		MFAAuthenticated: true,
	}
	if !g.CanAccess(principalARN, action, resourceARN, ctxWithMFA) {
		t.Error("Should allow access with MFA")
	}

	// Test 2: Access without MFA - should fail
	ctxWithoutMFA := &conditions.EvaluationContext{
		MFAAuthenticated: false,
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxWithoutMFA) {
		t.Error("Should deny access without MFA")
	}
}

func TestCanAccessWithConditions_OrgIDRestriction(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/cross-account"
	resourceARN := "arn:aws:s3:::shared-bucket/*"
	action := "s3:GetObject"

	// Add edge with organization ID restriction
	orgCondition := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:PrincipalOrgID": "o-123456",
		},
	}
	g.AddEdgeWithConditions(principalARN, action, resourceARN, false, orgCondition, "AllowFromOrg")

	// Test 1: Access from correct org - should pass
	ctxCorrectOrg := &conditions.EvaluationContext{
		PrincipalOrgID: "o-123456",
	}
	if !g.CanAccess(principalARN, action, resourceARN, ctxCorrectOrg) {
		t.Error("Should allow access from correct org")
	}

	// Test 2: Access from different org - should fail
	ctxWrongOrg := &conditions.EvaluationContext{
		PrincipalOrgID: "o-999999",
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxWrongOrg) {
		t.Error("Should deny access from different org")
	}
}

func TestCanAccessWithConditions_DenyWithCondition(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/developer"
	resourceARN := "arn:aws:s3:::production/*"
	action := "s3:*"

	// Add allow for all S3
	g.AddEdge(principalARN, "s3:*", "*", false)

	// Add deny for production bucket unless from office IP
	denyCondition := map[string]map[string]interface{}{
		"NotIpAddress": {
			"aws:SourceIp": "203.0.113.0/24",
		},
	}
	g.AddEdgeWithConditions(principalARN, action, resourceARN, true, denyCondition, "DenyProdFromNonOfficeIP")

	// Test 1: Access from office IP - should pass (deny condition doesn't match)
	ctxOfficeIP := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if !g.CanAccess(principalARN, "s3:GetObject", resourceARN, ctxOfficeIP) {
		t.Error("Should allow access to production from office IP")
	}

	// Test 2: Access from home IP - should fail (deny condition matches)
	ctxHomeIP := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if g.CanAccess(principalARN, "s3:GetObject", resourceARN, ctxHomeIP) {
		t.Error("Should deny access to production from non-office IP")
	}
}

func TestCanAccessWithConditions_MultipleConditions(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/admin"
	resourceARN := "*"
	action := "*"

	// Add edge with multiple conditions (IP + MFA)
	multiCondition := map[string]map[string]interface{}{
		"IpAddress": {
			"aws:SourceIp": "203.0.113.0/24",
		},
		"Bool": {
			"aws:MultiFactorAuthPresent": true,
		},
	}
	g.AddEdgeWithConditions(principalARN, action, resourceARN, false, multiCondition, "RequireIPAndMFA")

	// Test 1: Both conditions met - should pass
	ctxBoth := &conditions.EvaluationContext{
		SourceIP:         "203.0.113.50",
		MFAAuthenticated: true,
	}
	if !g.CanAccess(principalARN, action, resourceARN, ctxBoth) {
		t.Error("Should allow when both conditions met")
	}

	// Test 2: Only IP condition met - should fail
	ctxOnlyIP := &conditions.EvaluationContext{
		SourceIP:         "203.0.113.50",
		MFAAuthenticated: false,
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxOnlyIP) {
		t.Error("Should deny when MFA condition not met")
	}

	// Test 3: Only MFA condition met - should fail
	ctxOnlyMFA := &conditions.EvaluationContext{
		SourceIP:         "192.0.2.1",
		MFAAuthenticated: true,
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxOnlyMFA) {
		t.Error("Should deny when IP condition not met")
	}

	// Test 4: Neither condition met - should fail
	ctxNeither := &conditions.EvaluationContext{
		SourceIP:         "192.0.2.1",
		MFAAuthenticated: false,
	}
	if g.CanAccess(principalARN, action, resourceARN, ctxNeither) {
		t.Error("Should deny when no conditions met")
	}
}

func TestBuildWithConditions(t *testing.T) {
	// Test that Build() preserves conditions from policy statements
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "AllowS3FromOffice",
				Effect: types.EffectAllow,
				Action: "s3:*",
				Resource: "arn:aws:s3:::bucket/*",
				Condition: map[string]map[string]interface{}{
					"IpAddress": {
						"aws:SourceIp": "203.0.113.0/24",
					},
				},
			},
		},
	}

	principal := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/alice",
		Type:     types.PrincipalTypeUser,
		Name:     "alice",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{principal},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Verify condition is enforced
	ctxAllowed := &conditions.EvaluationContext{SourceIP: "203.0.113.50"}
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::bucket/key.txt", ctxAllowed) {
		t.Error("Should allow from office IP")
	}

	ctxDenied := &conditions.EvaluationContext{SourceIP: "192.0.2.1"}
	if g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::bucket/key.txt", ctxDenied) {
		t.Error("Should deny from non-office IP")
	}
}
