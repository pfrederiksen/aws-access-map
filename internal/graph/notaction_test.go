package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestCanAccess_NotActionAllowAllExceptS3Delete tests NotAction allowing all except s3:Delete*
func TestCanAccess_NotActionAllowAllExceptS3Delete(t *testing.T) {
	g := New()

	// User with policy: Allow all actions except s3:Delete*
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Sid:       "AllowAllExceptS3Delete",
						Effect:    types.EffectAllow,
						NotAction: []string{"s3:Delete*"},
						Resource:  "*",
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	if err := g.addPolicyEdges(user.ARN, user.Policies[0]); err != nil {
		t.Fatalf("Failed to add policy edges: %v", err)
	}

	// Should allow s3:GetObject (not excluded)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::bucket/key") {
		t.Error("Should allow s3:GetObject (not in NotAction)")
	}

	// Should allow s3:PutObject (not excluded)
	if !g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::bucket/key") {
		t.Error("Should allow s3:PutObject (not in NotAction)")
	}

	// Should NOT allow s3:DeleteObject (excluded by NotAction)
	if g.CanAccess(user.ARN, "s3:DeleteObject", "arn:aws:s3:::bucket/key") {
		t.Error("Should NOT allow s3:DeleteObject (excluded by NotAction)")
	}

	// Should NOT allow s3:DeleteBucket (excluded by NotAction)
	if g.CanAccess(user.ARN, "s3:DeleteBucket", "arn:aws:s3:::bucket") {
		t.Error("Should NOT allow s3:DeleteBucket (excluded by NotAction)")
	}

	// Should allow iam:CreateUser (not excluded)
	if !g.CanAccess(user.ARN, "iam:CreateUser", "arn:aws:iam::123456789012:user/newuser") {
		t.Error("Should allow iam:CreateUser (not in NotAction)")
	}

	// Should allow ec2:DescribeInstances (not excluded)
	if !g.CanAccess(user.ARN, "ec2:DescribeInstances", "*") {
		t.Error("Should allow ec2:DescribeInstances (not in NotAction)")
	}
}

// TestCanAccess_NotResourceAllowAllExceptProduction tests NotResource allowing all except production resources
func TestCanAccess_NotResourceAllowAllExceptProduction(t *testing.T) {
	g := New()

	// User with policy: Allow all S3 actions except on production bucket
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Sid:         "AllowS3ExceptProduction",
						Effect:      types.EffectAllow,
						Action:      "s3:*",
						NotResource: []string{"arn:aws:s3:::production-*/*", "arn:aws:s3:::production-*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	if err := g.addPolicyEdges(user.ARN, user.Policies[0]); err != nil {
		t.Fatalf("Failed to add policy edges: %v", err)
	}

	// Should allow access to dev bucket (not excluded)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::dev-bucket/file.txt") {
		t.Error("Should allow access to dev bucket (not in NotResource)")
	}

	// Should allow access to staging bucket (not excluded)
	if !g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::staging-data/file.txt") {
		t.Error("Should allow access to staging bucket (not in NotResource)")
	}

	// Should NOT allow access to production bucket (excluded by NotResource)
	if g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should NOT allow access to production bucket (excluded by NotResource)")
	}

	// Should NOT allow access to production-app bucket (excluded by NotResource)
	if g.CanAccess(user.ARN, "s3:DeleteObject", "arn:aws:s3:::production-app/file.txt") {
		t.Error("Should NOT allow access to production-app bucket (excluded by NotResource)")
	}

	// Should allow access to test bucket (not excluded)
	if !g.CanAccess(user.ARN, "s3:ListBucket", "arn:aws:s3:::test-bucket") {
		t.Error("Should allow access to test bucket (not in NotResource)")
	}
}

// TestCanAccess_NotActionAndNotResource tests combined NotAction and NotResource
func TestCanAccess_NotActionAndNotResource(t *testing.T) {
	g := New()

	// User with policy: Allow all actions except Delete, on all resources except production
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Sid:         "AllowExceptDeleteAndProduction",
						Effect:      types.EffectAllow,
						NotAction:   []string{"*:Delete*"},
						NotResource: []string{"arn:aws:s3:::production-*/*"},
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	if err := g.addPolicyEdges(user.ARN, user.Policies[0]); err != nil {
		t.Fatalf("Failed to add policy edges: %v", err)
	}

	// Should allow s3:GetObject on dev bucket (not excluded by either)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::dev-bucket/file.txt") {
		t.Error("Should allow s3:GetObject on dev bucket")
	}

	// Should NOT allow s3:DeleteObject on dev bucket (excluded by NotAction)
	if g.CanAccess(user.ARN, "s3:DeleteObject", "arn:aws:s3:::dev-bucket/file.txt") {
		t.Error("Should NOT allow s3:DeleteObject on dev bucket (excluded by NotAction)")
	}

	// Should NOT allow s3:GetObject on production bucket (excluded by NotResource)
	if g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should NOT allow s3:GetObject on production bucket (excluded by NotResource)")
	}

	// Should NOT allow s3:DeleteObject on production bucket (excluded by both)
	if g.CanAccess(user.ARN, "s3:DeleteObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should NOT allow s3:DeleteObject on production bucket (excluded by both)")
	}

	// Should allow iam:CreateUser (not excluded by NotAction wildcard is *:Delete*)
	if !g.CanAccess(user.ARN, "iam:CreateUser", "arn:aws:iam::123456789012:user/newuser") {
		t.Error("Should allow iam:CreateUser (not excluded)")
	}

	// Should NOT allow iam:DeleteUser (excluded by NotAction)
	if g.CanAccess(user.ARN, "iam:DeleteUser", "arn:aws:iam::123456789012:user/olduser") {
		t.Error("Should NOT allow iam:DeleteUser (excluded by NotAction)")
	}
}

// TestCanAccess_DenyWithNotAction tests deny statements with NotAction
func TestCanAccess_DenyWithNotAction(t *testing.T) {
	g := New()

	// User with allow all, but deny all except Read on production
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Sid:      "AllowAll",
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
					{
						Sid:       "DenyAllExceptReadOnProduction",
						Effect:    types.EffectDeny,
						NotAction: []string{"s3:Get*", "s3:List*"},
						Resource:  "arn:aws:s3:::production-*/*",
					},
				},
			},
		},
	}

	g.AddPrincipal(user)
	if err := g.addPolicyEdges(user.ARN, user.Policies[0]); err != nil {
		t.Fatalf("Failed to add policy edges: %v", err)
	}

	// Should allow s3:GetObject on production (not denied by NotAction)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should allow s3:GetObject on production (not denied)")
	}

	// Should allow s3:ListBucket on production (not denied by NotAction)
	if !g.CanAccess(user.ARN, "s3:ListBucket", "arn:aws:s3:::production-data/") {
		t.Error("Should allow s3:ListBucket on production (not denied)")
	}

	// Should NOT allow s3:PutObject on production (denied, not in NotAction exclusion)
	if g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should NOT allow s3:PutObject on production (denied)")
	}

	// Should NOT allow s3:DeleteObject on production (denied, not in NotAction exclusion)
	if g.CanAccess(user.ARN, "s3:DeleteObject", "arn:aws:s3:::production-data/file.txt") {
		t.Error("Should NOT allow s3:DeleteObject on production (denied)")
	}

	// Should allow s3:PutObject on dev bucket (deny doesn't apply)
	if !g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::dev-bucket/file.txt") {
		t.Error("Should allow s3:PutObject on dev bucket (deny doesn't apply)")
	}
}

// TestCanAccess_GroupWithNotAction tests group inheritance with NotAction
func TestCanAccess_GroupWithNotAction(t *testing.T) {
	g := New()

	// Group with NotAction policy
	group := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:group/Developers",
		Type: types.PrincipalTypeGroup,
		Name: "Developers",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Sid:       "AllowAllExceptIAM",
						Effect:    types.EffectAllow,
						NotAction: []string{"iam:*"},
						Resource:  "*",
					},
				},
			},
		},
	}

	// User in the group
	user := &types.Principal{
		ARN:              "arn:aws:iam::123456789012:user/alice",
		Type:             types.PrincipalTypeUser,
		Name:             "alice",
		GroupMemberships: []string{group.ARN},
		Policies:         []types.PolicyDocument{},
	}

	g.AddPrincipal(group)
	if err := g.addPolicyEdges(group.ARN, group.Policies[0]); err != nil {
		t.Fatalf("Failed to add policy edges for group: %v", err)
	}

	g.AddPrincipal(user)

	// User should inherit group's NotAction policy
	// Should allow s3:GetObject (not excluded by NotAction)
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::bucket/key") {
		t.Error("User should allow s3:GetObject via group (not excluded)")
	}

	// Should allow ec2:DescribeInstances (not excluded by NotAction)
	if !g.CanAccess(user.ARN, "ec2:DescribeInstances", "*") {
		t.Error("User should allow ec2:DescribeInstances via group (not excluded)")
	}

	// Should NOT allow iam:CreateUser (excluded by NotAction)
	if g.CanAccess(user.ARN, "iam:CreateUser", "arn:aws:iam::123456789012:user/newuser") {
		t.Error("User should NOT allow iam:CreateUser via group (excluded by NotAction)")
	}

	// Should NOT allow iam:DeleteRole (excluded by NotAction)
	if g.CanAccess(user.ARN, "iam:DeleteRole", "arn:aws:iam::123456789012:role/oldrole") {
		t.Error("User should NOT allow iam:DeleteRole via group (excluded by NotAction)")
	}
}

// TestCanAccess_ResourcePolicyWithNotAction tests resource-based policies with NotAction
func TestCanAccess_ResourcePolicyWithNotAction(t *testing.T) {
	g := New()

	// Public principal for resource policy
	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public (Anonymous)",
	}
	g.AddPrincipal(publicPrincipal)

	// S3 bucket with resource policy: Allow all except Delete for everyone
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::public-bucket",
		Type: types.ResourceTypeS3,
		Name: "public-bucket",
		ResourcePolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Sid:       "AllowPublicReadOnly",
					Effect:    types.EffectAllow,
					Principal: "*",
					NotAction: []string{"s3:Delete*", "s3:Put*"},
					Resource:  "arn:aws:s3:::public-bucket/*",
				},
			},
		},
	}

	g.AddResource(bucket)
	if err := g.addResourcePolicyEdges(bucket.ARN, *bucket.ResourcePolicy); err != nil {
		t.Fatalf("Failed to add resource policy edges: %v", err)
	}

	// Should allow s3:GetObject (not excluded)
	if !g.CanAccess("*", "s3:GetObject", "arn:aws:s3:::public-bucket/file.txt") {
		t.Error("Should allow public s3:GetObject (not excluded by NotAction)")
	}

	// Should allow s3:ListBucket (not excluded)
	if !g.CanAccess("*", "s3:ListBucket", "arn:aws:s3:::public-bucket/") {
		t.Error("Should allow public s3:ListBucket (not excluded by NotAction)")
	}

	// Should NOT allow s3:PutObject (excluded by NotAction)
	if g.CanAccess("*", "s3:PutObject", "arn:aws:s3:::public-bucket/file.txt") {
		t.Error("Should NOT allow public s3:PutObject (excluded by NotAction)")
	}

	// Should NOT allow s3:DeleteObject (excluded by NotAction)
	if g.CanAccess("*", "s3:DeleteObject", "arn:aws:s3:::public-bucket/file.txt") {
		t.Error("Should NOT allow public s3:DeleteObject (excluded by NotAction)")
	}
}

// TestBuild_NotActionIntegration tests Build() preserves NotAction/NotResource
func TestBuild_NotActionIntegration(t *testing.T) {
	// User with NotAction policy
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/developer",
		Type: types.PrincipalTypeUser,
		Name: "developer",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:      types.EffectAllow,
						NotAction:   []string{"iam:*"},
						NotResource: []string{"arn:aws:s3:::sensitive-*/*"},
					},
				},
			},
		},
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{user},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Verify NotAction exclusion works
	if g.CanAccess(user.ARN, "iam:CreateUser", "*") {
		t.Error("Should NOT allow iam:CreateUser (excluded by NotAction)")
	}

	// Verify actions not in NotAction are allowed
	if !g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::normal-bucket/file.txt") {
		t.Error("Should allow s3:GetObject on normal bucket")
	}

	// Verify NotResource exclusion works
	if g.CanAccess(user.ARN, "s3:GetObject", "arn:aws:s3:::sensitive-data/secret.txt") {
		t.Error("Should NOT allow access to sensitive bucket (excluded by NotResource)")
	}

	// Verify resources not in NotResource are allowed
	if !g.CanAccess(user.ARN, "s3:PutObject", "arn:aws:s3:::public-bucket/file.txt") {
		t.Error("Should allow s3:PutObject on public bucket")
	}
}
