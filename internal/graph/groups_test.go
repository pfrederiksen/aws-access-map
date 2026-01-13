package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestCanAccess_UserViaGroup tests that a user inherits permissions from their group
func TestCanAccess_UserViaGroup(t *testing.T) {
	g := New()

	// Create a group with S3 read access
	group := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/Developers",
		Type: types.PrincipalTypeGroup,
		Name: "Developers",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:GetObject"},
						Resource: []string{"arn:aws:s3:::my-bucket/*"},
					},
				},
			},
		},
	}

	// Create a user who is a member of the group
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/alice",
		Type:             types.PrincipalTypeUser,
		Name:             "alice",
		GroupMemberships: []string{"arn:aws:iam::123456789012:group/Developers"},
		Policies:         []types.PolicyDocument{}, // User has no direct policies
	}

	g.AddPrincipal(group)
	for _, policy := range group.Policies {
		if err := g.addPolicyEdges(group.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for group: %v", err)
		}
	}

	g.AddPrincipal(user)

	// User should have access through group membership
	canAccess := g.CanAccess("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt")
	if !canAccess {
		t.Error("User should have access to S3 through group membership")
	}
}

// TestCanAccess_UserInMultipleGroups tests that a user inherits permissions from all their groups
func TestCanAccess_UserInMultipleGroups(t *testing.T) {
	g := New()

	// Create first group with S3 access
	group1 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/S3Users",
		Type: types.PrincipalTypeGroup,
		Name: "S3Users",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:GetObject"},
						Resource: []string{"arn:aws:s3:::*"},
					},
				},
			},
		},
	}

	// Create second group with DynamoDB access
	group2 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/DynamoDBUsers",
		Type: types.PrincipalTypeGroup,
		Name: "DynamoDBUsers",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"dynamodb:GetItem"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	// Create user in both groups
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/bob",
		Type: types.PrincipalTypeUser,
		Name: "bob",
		GroupMemberships: []string{
			"arn:aws:iam::123456789012:group/S3Users",
			"arn:aws:iam::123456789012:group/DynamoDBUsers",
		},
		Policies: []types.PolicyDocument{},
	}

	g.AddPrincipal(group1)
	for _, policy := range group1.Policies {
		if err := g.addPolicyEdges(group1.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for group1: %v", err)
		}
	}

	g.AddPrincipal(group2)
	for _, policy := range group2.Policies {
		if err := g.addPolicyEdges(group2.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for group2: %v", err)
		}
	}

	g.AddPrincipal(user)

	// User should have S3 access from group1
	canAccessS3 := g.CanAccess("arn:aws:iam::123456789012:user/bob", "s3:GetObject", "arn:aws:s3:::bucket/file.txt")
	if !canAccessS3 {
		t.Error("User should have S3 access through S3Users group")
	}

	// User should have DynamoDB access from group2
	canAccessDynamoDB := g.CanAccess("arn:aws:iam::123456789012:user/bob", "dynamodb:GetItem", "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable")
	if !canAccessDynamoDB {
		t.Error("User should have DynamoDB access through DynamoDBUsers group")
	}
}

// TestCanAccess_GroupDenyOverridesUserAllow tests that deny rules from groups override user allows
func TestCanAccess_GroupDenyOverridesUserAllow(t *testing.T) {
	g := New()

	// Create group with explicit deny on s3:DeleteObject
	group := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/Restricted",
		Type: types.PrincipalTypeGroup,
		Name: "Restricted",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectDeny,
						Action:   []string{"s3:DeleteObject"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	// Create user with explicit allow on all S3 actions
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/charlie",
		Type:             types.PrincipalTypeUser,
		Name:             "charlie",
		GroupMemberships: []string{"arn:aws:iam::123456789012:group/Restricted"},
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:*"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(group)
	for _, policy := range group.Policies {
		if err := g.addPolicyEdges(group.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for group: %v", err)
		}
	}

	g.AddPrincipal(user)
	for _, policy := range user.Policies {
		if err := g.addPolicyEdges(user.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for user: %v", err)
		}
	}

	// User should be able to GetObject (group doesn't deny it)
	canGet := g.CanAccess("arn:aws:iam::123456789012:user/charlie", "s3:GetObject", "arn:aws:s3:::bucket/file.txt")
	if !canGet {
		t.Error("User should have GetObject access (not denied by group)")
	}

	// User should NOT be able to DeleteObject (group denies it)
	canDelete := g.CanAccess("arn:aws:iam::123456789012:user/charlie", "s3:DeleteObject", "arn:aws:s3:::bucket/file.txt")
	if canDelete {
		t.Error("User should NOT have DeleteObject access (denied by group)")
	}
}

// TestCanAccess_UserNoGroups tests that users without groups still work correctly
func TestCanAccess_UserNoGroups(t *testing.T) {
	g := New()

	// Create user with direct policy (no group memberships)
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/dave",
		Type:             types.PrincipalTypeUser,
		Name:             "dave",
		GroupMemberships: nil, // No groups
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:GetObject"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	for _, policy := range user.Policies {
		if err := g.addPolicyEdges(user.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for user: %v", err)
		}
	}

	// User should have access through direct policy
	canAccess := g.CanAccess("arn:aws:iam::123456789012:user/dave", "s3:GetObject", "arn:aws:s3:::bucket/file.txt")
	if !canAccess {
		t.Error("User should have access through direct policy")
	}
}

// TestCanAccess_GroupWildcardMatching tests wildcard matching in group policies
func TestCanAccess_GroupWildcardMatching(t *testing.T) {
	g := New()

	// Create group with wildcard S3 actions
	group := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/S3Admins",
		Type: types.PrincipalTypeGroup,
		Name: "S3Admins",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:Get*"}, // Wildcard action
						Resource: []string{"arn:aws:s3:::production-*/*"}, // Wildcard resource
					},
				},
			},
		},
	}

	// Create user in the group
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/eve",
		Type:             types.PrincipalTypeUser,
		Name:             "eve",
		GroupMemberships: []string{"arn:aws:iam::123456789012:group/S3Admins"},
		Policies:         []types.PolicyDocument{},
	}

	g.AddPrincipal(group)
	for _, policy := range group.Policies {
		if err := g.addPolicyEdges(group.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for group: %v", err)
		}
	}

	g.AddPrincipal(user)

	// User should have GetObject on production buckets
	canAccessProd := g.CanAccess("arn:aws:iam::123456789012:user/eve", "s3:GetObject", "arn:aws:s3:::production-data/file.txt")
	if !canAccessProd {
		t.Error("User should have access to production-* buckets through group")
	}

	// User should NOT have access to non-production buckets
	canAccessDev := g.CanAccess("arn:aws:iam::123456789012:user/eve", "s3:GetObject", "arn:aws:s3:::dev-data/file.txt")
	if canAccessDev {
		t.Error("User should NOT have access to non-production buckets")
	}

	// User should NOT have PutObject (doesn't match Get*)
	canPut := g.CanAccess("arn:aws:iam::123456789012:user/eve", "s3:PutObject", "arn:aws:s3:::production-data/file.txt")
	if canPut {
		t.Error("User should NOT have PutObject access (doesn't match Get* wildcard)")
	}
}

// TestCanAccess_EmptyGroupMemberships tests that empty group membership array works
func TestCanAccess_EmptyGroupMemberships(t *testing.T) {
	g := New()

	// Create user with empty group memberships array
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/frank",
		Type:             types.PrincipalTypeUser,
		Name:             "frank",
		GroupMemberships: []string{}, // Empty array (different from nil)
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:GetObject"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	for _, policy := range user.Policies {
		if err := g.addPolicyEdges(user.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for user: %v", err)
		}
	}

	// User should still have access through direct policy
	canAccess := g.CanAccess("arn:aws:iam::123456789012:user/frank", "s3:GetObject", "arn:aws:s3:::bucket/file.txt")
	if !canAccess {
		t.Error("User with empty group memberships should have access through direct policy")
	}
}

// TestCanAccess_NonExistentGroupMembership tests handling of references to non-existent groups
func TestCanAccess_NonExistentGroupMembership(t *testing.T) {
	g := New()

	// Create user referencing a group that doesn't exist in the graph
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/grace",
		Type:             types.PrincipalTypeUser,
		Name:             "grace",
		GroupMemberships: []string{"arn:aws:iam::123456789012:group/NonExistent"},
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   []string{"s3:GetObject"},
						Resource: []string{"*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	for _, policy := range user.Policies {
		if err := g.addPolicyEdges(user.ARN, policy); err != nil {
			t.Fatalf("Failed to add policy edges for user: %v", err)
		}
	}

	// User should still have access through direct policy (non-existent group is ignored)
	canAccess := g.CanAccess("arn:aws:iam::123456789012:user/grace", "s3:GetObject", "arn:aws:s3:::bucket/file.txt")
	if !canAccess {
		t.Error("User should have access through direct policy (non-existent group ignored)")
	}

	// User should NOT gain unexpected access from non-existent group
	canAccessDynamoDB := g.CanAccess("arn:aws:iam::123456789012:user/grace", "dynamodb:GetItem", "*")
	if canAccessDynamoDB {
		t.Error("User should NOT have access to actions not in their direct policy")
	}
}
