package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestRealWorld_IPRestrictedAdmin tests a real-world scenario:
// Admin user with full access, but only from office IP range
func TestRealWorld_IPRestrictedAdmin(t *testing.T) {
	// Policy: Allow all actions, but only from office IP (203.0.113.0/24)
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "AllowFromOfficeIP",
				Effect: types.EffectAllow,
				Action: "*",
				Resource: "*",
				Condition: map[string]map[string]interface{}{
					"IpAddress": {
						"aws:SourceIp": "203.0.113.0/24",
					},
				},
			},
		},
	}

	principal := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/admin",
		Type:     types.PrincipalTypeUser,
		Name:     "admin",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{principal},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Access from office IP - should work
	officeCtx := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::sensitive-bucket/*", officeCtx) {
		t.Error("Should allow admin access from office IP")
	}

	// Test 2: Access from home IP - should be denied
	homeCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::sensitive-bucket/*", homeCtx) {
		t.Error("Should deny admin access from home IP")
	}

	// Test 3: Without context (permissive default) - should work
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::sensitive-bucket/*") {
		t.Error("Should allow with permissive default context")
	}
}

// TestRealWorld_MFAProtectedIAM tests MFA requirement for sensitive IAM operations
func TestRealWorld_MFAProtectedIAM(t *testing.T) {
	// Policy: Allow IAM operations only with MFA
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "ReadOnlyWithoutMFA",
				Effect: types.EffectAllow,
				Action: []interface{}{"iam:Get*", "iam:List*"},
				Resource: "*",
			},
			{
				Sid:    "WriteRequiresMFA",
				Effect: types.EffectAllow,
				Action: []interface{}{"iam:*"},
				Resource: "*",
				Condition: map[string]map[string]interface{}{
					"Bool": {
						"aws:MultiFactorAuthPresent": true,
					},
				},
			},
		},
	}

	principal := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/poweruser",
		Type:     types.PrincipalTypeUser,
		Name:     "poweruser",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{principal},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Read operations without MFA - should work
	noMFACtx := &conditions.EvaluationContext{
		MFAAuthenticated: false,
	}
	if !g.CanAccess(principal.ARN, "iam:ListUsers", "*", noMFACtx) {
		t.Error("Should allow read operations without MFA")
	}

	// Test 2: Write operations without MFA - should be denied
	if g.CanAccess(principal.ARN, "iam:DeleteUser", "arn:aws:iam::123456789012:user/test", noMFACtx) {
		t.Error("Should deny write operations without MFA")
	}

	// Test 3: Write operations with MFA - should work
	withMFACtx := &conditions.EvaluationContext{
		MFAAuthenticated: true,
	}
	if !g.CanAccess(principal.ARN, "iam:DeleteUser", "arn:aws:iam::123456789012:user/test", withMFACtx) {
		t.Error("Should allow write operations with MFA")
	}
}

// TestRealWorld_OrgRestrictedBucket tests cross-account access with organization restrictions
func TestRealWorld_OrgRestrictedBucket(t *testing.T) {
	// Cross-account user with policy to access shared bucket
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "AllowSharedBucket",
				Effect: types.EffectAllow,
				Action: "s3:*",
				Resource: "arn:aws:s3:::shared-bucket/*",
			},
		},
	}

	// S3 bucket policy: Allow access only from principals in organization o-123456
	bucketPolicy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:       "AllowFromOrganization",
				Effect:    types.EffectAllow,
				Principal: map[string]interface{}{"AWS": "*"},
				Action:    "s3:*",
				Resource:  "arn:aws:s3:::shared-bucket/*",
				Condition: map[string]map[string]interface{}{
					"StringEquals": {
						"aws:PrincipalOrgID": "o-123456",
					},
				},
			},
		},
	}

	// Cross-account user
	crossAccountUser := &types.Principal{
		ARN:      "arn:aws:iam::999888777666:user/external",
		Type:     types.PrincipalTypeUser,
		Name:     "external",
		Policies: []types.PolicyDocument{policy},
	}

	// Shared bucket resource with policy
	bucket := &types.Resource{
		ARN:           "arn:aws:s3:::shared-bucket",
		Type:          types.ResourceTypeS3,
		Name:          "shared-bucket",
		ResourcePolicy: &bucketPolicy,
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{crossAccountUser},
		Resources:  []*types.Resource{bucket},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Access from correct organization - should work (both identity AND resource policy allow)
	correctOrgCtx := &conditions.EvaluationContext{
		PrincipalOrgID: "o-123456",
	}

	// Check identity-based access first (should work without conditions)
	if !g.CanAccess(crossAccountUser.ARN, "s3:GetObject", "arn:aws:s3:::shared-bucket/file.txt", correctOrgCtx) {
		t.Error("Should allow access from user in correct organization")
	}

	// Test 2: Access from different organization - should still work via identity policy
	// (Note: In real AWS, you'd need BOTH identity and resource policy to allow, but our
	// graph model currently treats them as separate paths. This is a known limitation.)
	wrongOrgCtx := &conditions.EvaluationContext{
		PrincipalOrgID: "o-999999",
	}

	// Identity policy allows regardless of org, so this will pass
	// This test demonstrates that identity policies don't have the org restriction
	if !g.CanAccess(crossAccountUser.ARN, "s3:GetObject", "arn:aws:s3:::shared-bucket/file.txt", wrongOrgCtx) {
		t.Error("Identity policy allows access regardless of org (resource policy is separate)")
	}
}

// TestRealWorld_MultipleConditionsAND tests that all conditions must pass (AND logic)
func TestRealWorld_MultipleConditionsAND(t *testing.T) {
	// Policy: Allow only from office IP AND with MFA
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "RequireIPAndMFA",
				Effect: types.EffectAllow,
				Action: "*",
				Resource: "*",
				Condition: map[string]map[string]interface{}{
					"IpAddress": {
						"aws:SourceIp": "203.0.113.0/24",
					},
					"Bool": {
						"aws:MultiFactorAuthPresent": true,
					},
				},
			},
		},
	}

	principal := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/secureuser",
		Type:     types.PrincipalTypeUser,
		Name:     "secureuser",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{principal},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Both conditions met - should work
	bothCtx := &conditions.EvaluationContext{
		SourceIP:         "203.0.113.50",
		MFAAuthenticated: true,
	}
	if !g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::any-bucket", bothCtx) {
		t.Error("Should allow when both conditions are met")
	}

	// Test 2: Only IP condition met - should be denied
	onlyIPCtx := &conditions.EvaluationContext{
		SourceIP:         "203.0.113.50",
		MFAAuthenticated: false,
	}
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::any-bucket", onlyIPCtx) {
		t.Error("Should deny when MFA condition not met")
	}

	// Test 3: Only MFA condition met - should be denied
	onlyMFACtx := &conditions.EvaluationContext{
		SourceIP:         "192.0.2.1",
		MFAAuthenticated: true,
	}
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::any-bucket", onlyMFACtx) {
		t.Error("Should deny when IP condition not met")
	}

	// Test 4: Neither condition met - should be denied
	neitherCtx := &conditions.EvaluationContext{
		SourceIP:         "192.0.2.1",
		MFAAuthenticated: false,
	}
	if g.CanAccess(principal.ARN, "s3:DeleteBucket", "arn:aws:s3:::any-bucket", neitherCtx) {
		t.Error("Should deny when no conditions are met")
	}
}

// TestRealWorld_ExplicitDenyWithCondition tests that deny with matching condition blocks access
func TestRealWorld_ExplicitDenyWithCondition(t *testing.T) {
	// Policy: Allow all S3, but deny production bucket unless from office IP
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "AllowS3",
				Effect: types.EffectAllow,
				Action: "s3:*",
				Resource: "*",
			},
			{
				Sid:    "DenyProdFromNonOfficeIP",
				Effect: types.EffectDeny,
				Action: "s3:*",
				Resource: "arn:aws:s3:::production-bucket/*",
				Condition: map[string]map[string]interface{}{
					"NotIpAddress": {
						"aws:SourceIp": "203.0.113.0/24",
					},
				},
			},
		},
	}

	principal := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/developer",
		Type:     types.PrincipalTypeUser,
		Name:     "developer",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{principal},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Access dev bucket from anywhere - should work
	anyIPCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::dev-bucket/file.txt", anyIPCtx) {
		t.Error("Should allow access to dev bucket from any IP")
	}

	// Test 2: Access prod bucket from office IP - should work (deny condition doesn't match)
	officeIPCtx := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if !g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::production-bucket/file.txt", officeIPCtx) {
		t.Error("Should allow access to prod bucket from office IP")
	}

	// Test 3: Access prod bucket from home IP - should be denied (deny condition matches)
	homeIPCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if g.CanAccess(principal.ARN, "s3:GetObject", "arn:aws:s3:::production-bucket/file.txt", homeIPCtx) {
		t.Error("Should deny access to prod bucket from non-office IP")
	}
}

// TestRealWorld_ARNPatternMatching tests ARN-based condition evaluation
func TestRealWorld_ARNPatternMatching(t *testing.T) {
	// Policy: Allow S3 actions only for principals matching ARN pattern
	policy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Sid:    "AllowFromDevTeam",
				Effect: types.EffectAllow,
				Action: "s3:*",
				Resource: "arn:aws:s3:::team-bucket/*",
				Condition: map[string]map[string]interface{}{
					"ArnLike": {
						"aws:PrincipalArn": "arn:aws:iam::123456789012:user/dev-*",
					},
				},
			},
		},
	}

	devUser := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/dev-alice",
		Type:     types.PrincipalTypeUser,
		Name:     "dev-alice",
		Policies: []types.PolicyDocument{policy},
	}

	opsUser := &types.Principal{
		ARN:      "arn:aws:iam::123456789012:user/ops-bob",
		Type:     types.PrincipalTypeUser,
		Name:     "ops-bob",
		Policies: []types.PolicyDocument{policy},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{devUser, opsUser},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Test 1: Dev user (matches ARN pattern) - should work
	devCtx := &conditions.EvaluationContext{
		PrincipalARN: "arn:aws:iam::123456789012:user/dev-alice",
	}
	if !g.CanAccess(devUser.ARN, "s3:PutObject", "arn:aws:s3:::team-bucket/file.txt", devCtx) {
		t.Error("Should allow dev user matching ARN pattern")
	}

	// Test 2: Ops user (doesn't match ARN pattern) - should be denied
	opsCtx := &conditions.EvaluationContext{
		PrincipalARN: "arn:aws:iam::123456789012:user/ops-bob",
	}
	if g.CanAccess(opsUser.ARN, "s3:PutObject", "arn:aws:s3:::team-bucket/file.txt", opsCtx) {
		t.Error("Should deny ops user not matching ARN pattern")
	}
}
