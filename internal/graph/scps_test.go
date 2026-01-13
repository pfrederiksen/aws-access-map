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
			ID:      "scp-allow-and-deny",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
				{
					Effect:   types.EffectDeny,
					Action:   "s3:DeleteBucket",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Should be blocked by explicit deny
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to block s3:DeleteBucket")
	}

	// Should NOT be blocked (allowed by Allow statement, no deny)
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
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
				{
					Effect:   types.EffectDeny,
					Action:   "s3:*",
					Resource: "*",
				},
			},
		},
	}

	ctx := conditions.NewDefaultContext()

	// Should block all S3 actions (allowed then denied)
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected SCP to block s3:DeleteBucket with wildcard")
	}

	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt", ctx) {
		t.Error("Expected SCP to block s3:GetObject with wildcard")
	}

	// Should NOT block non-S3 actions (allowed, no deny)
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
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
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

	// From office IP - should NOT be blocked (allowed, deny doesn't match)
	officeCtx := &conditions.EvaluationContext{
		SourceIP: "203.0.113.50",
	}
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::bucket/file.txt", officeCtx) {
		t.Error("Expected office IP to NOT be blocked")
	}

	// From home IP - should be blocked (allowed, but then denied by condition)
	homeCtx := &conditions.EvaluationContext{
		SourceIP: "192.0.2.1",
	}
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:GetObject", "arn:aws:s3:::bucket/file.txt", homeCtx) {
		t.Error("Expected home IP to be blocked")
	}
}

// TestIsBlockedBySCP_ImplicitDeny tests that actions not explicitly allowed are implicitly denied
func TestIsBlockedBySCP_ImplicitDeny(t *testing.T) {
	g := New()
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-allow-s3-only",
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

	ctx := conditions.NewDefaultContext()

	// S3 actions should be allowed (explicit allow exists)
	if g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "s3:DeleteBucket", "arn:aws:s3:::my-bucket", ctx) {
		t.Error("Expected s3:DeleteBucket to be allowed (explicit allow)")
	}

	// Non-S3 actions should be implicitly denied (no allow statement)
	if !g.isBlockedBySCP("arn:aws:iam::123456789012:user/alice", "iam:CreateUser", "*", ctx) {
		t.Error("Expected iam:CreateUser to be blocked (implicit deny)")
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

	// Add SCP that allows S3 but denies bucket deletion
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-bucket-delete",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
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

	// Add multiple SCPs with different constraints
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-deny-iam",
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
		{
			ID:      "scp-deny-s3-delete",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
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

	// SCP allows S3 but denies access only to production buckets
	g.scps = []types.PolicyDocument{
		{
			ID:      "scp-protect-prod",
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "*",
					Resource: "*",
				},
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

// TestFilterSCPsForAccount tests SCP filtering based on attachments and OU hierarchy
func TestFilterSCPsForAccount(t *testing.T) {
	// Test account ID
	testAccountID := "123456789012"
	otherAccountID := "999999999999"

	// Test OU IDs
	parentOU1 := "ou-1111-11111111"
	parentOU2 := "ou-2222-22222222"
	otherOU := "ou-9999-99999999"

	// Sample SCPs
	scpRoot := types.PolicyDocument{
		ID:      "scp-root",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{Effect: types.EffectAllow, Action: "*", Resource: "*"},
		},
	}

	scpAccount := types.PolicyDocument{
		ID:      "scp-account",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{Effect: types.EffectDeny, Action: "iam:*", Resource: "*"},
		},
	}

	scpOU := types.PolicyDocument{
		ID:      "scp-ou",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{Effect: types.EffectDeny, Action: "s3:*", Resource: "*"},
		},
	}

	scpMultiTarget := types.PolicyDocument{
		ID:      "scp-multi",
		Version: "2012-10-17",
		Statements: []types.Statement{
			{Effect: types.EffectDeny, Action: "ec2:*", Resource: "*"},
		},
	}

	tests := []struct {
		name        string
		accountID   string
		attachments []types.SCPAttachment
		ouHierarchy *types.OUHierarchy
		wantCount   int
		wantIDs     []string
	}{
		{
			name:      "ROOT target applies to all accounts",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpRoot,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeRoot, ID: "r-1111"},
					},
				},
			},
			ouHierarchy: nil,
			wantCount:   1,
			wantIDs:     []string{"scp-root"},
		},
		{
			name:      "ACCOUNT target matches specific account",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpAccount,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeAccount, ID: testAccountID},
					},
				},
			},
			ouHierarchy: nil,
			wantCount:   1,
			wantIDs:     []string{"scp-account"},
		},
		{
			name:      "ACCOUNT target doesn't match different account",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpAccount,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeAccount, ID: otherAccountID},
					},
				},
			},
			ouHierarchy: nil,
			wantCount:   0,
			wantIDs:     []string{},
		},
		{
			name:      "ORGANIZATIONAL_UNIT with hierarchy - OU in hierarchy",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpOU,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeOrganizationalUnit, ID: parentOU1},
					},
				},
			},
			ouHierarchy: &types.OUHierarchy{
				AccountID: testAccountID,
				ParentOUs: []string{parentOU1, parentOU2},
			},
			wantCount: 1,
			wantIDs:   []string{"scp-ou"},
		},
		{
			name:      "ORGANIZATIONAL_UNIT with hierarchy - OU not in hierarchy",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpOU,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeOrganizationalUnit, ID: otherOU},
					},
				},
			},
			ouHierarchy: &types.OUHierarchy{
				AccountID: testAccountID,
				ParentOUs: []string{parentOU1, parentOU2},
			},
			wantCount: 0,
			wantIDs:   []string{},
		},
		{
			name:      "ORGANIZATIONAL_UNIT without hierarchy - conservative fallback",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpOU,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeOrganizationalUnit, ID: otherOU},
					},
				},
			},
			ouHierarchy: nil, // No hierarchy available
			wantCount:   1,   // Conservatively include it
			wantIDs:     []string{"scp-ou"},
		},
		{
			name:      "Multiple targets per SCP - one matches",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpMultiTarget,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeAccount, ID: otherAccountID}, // Doesn't match
						{Type: types.SCPTargetTypeAccount, ID: testAccountID},  // Matches
					},
				},
			},
			ouHierarchy: nil,
			wantCount:   1,
			wantIDs:     []string{"scp-multi"},
		},
		{
			name:      "Multiple attachments - mixed matching",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpRoot,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeRoot, ID: "r-1111"},
					},
				},
				{
					Policy: scpAccount,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeAccount, ID: testAccountID},
					},
				},
				{
					Policy: scpOU,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeAccount, ID: otherAccountID}, // Doesn't match
					},
				},
			},
			ouHierarchy: nil,
			wantCount:   2,
			wantIDs:     []string{"scp-root", "scp-account"},
		},
		{
			name:        "No attachments returns empty list",
			accountID:   testAccountID,
			attachments: []types.SCPAttachment{},
			ouHierarchy: nil,
			wantCount:   0,
			wantIDs:     []string{},
		},
		{
			name:      "Complex hierarchy with multiple OUs",
			accountID: testAccountID,
			attachments: []types.SCPAttachment{
				{
					Policy: scpRoot,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeRoot, ID: "r-1111"},
					},
				},
				{
					Policy: scpOU,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeOrganizationalUnit, ID: parentOU2},
					},
				},
				{
					Policy: scpAccount,
					Targets: []types.SCPTarget{
						{Type: types.SCPTargetTypeOrganizationalUnit, ID: otherOU},
					},
				},
			},
			ouHierarchy: &types.OUHierarchy{
				AccountID: testAccountID,
				ParentOUs: []string{parentOU1, parentOU2},
			},
			wantCount: 2,
			wantIDs:   []string{"scp-root", "scp-ou"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterSCPsForAccount(tt.accountID, tt.attachments, tt.ouHierarchy)

			if len(result) != tt.wantCount {
				t.Errorf("filterSCPsForAccount() returned %d SCPs, want %d", len(result), tt.wantCount)
			}

			// Verify the correct SCPs were included
			resultIDs := make(map[string]bool)
			for _, scp := range result {
				resultIDs[scp.ID] = true
			}

			for _, wantID := range tt.wantIDs {
				if !resultIDs[wantID] {
					t.Errorf("Expected SCP %q to be included, but it wasn't", wantID)
				}
			}

			// Verify no unexpected SCPs were included
			for resultID := range resultIDs {
				found := false
				for _, wantID := range tt.wantIDs {
					if resultID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Unexpected SCP %q was included", resultID)
				}
			}
		})
	}
}
