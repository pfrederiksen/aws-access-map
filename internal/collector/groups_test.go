package collector

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestResolveGroupMemberships tests the group membership resolution logic
func TestResolveGroupMemberships(t *testing.T) {
	tests := []struct {
		name             string
		users            []*types.Principal
		groupMemberships map[string][]string
		wantMemberships  map[string][]string // userARN -> expected group ARNs
	}{
		{
			name: "Single user in single group",
			users: []*types.Principal{
				{
					ARN:  "arn:aws:iam::123456789012:user/alice",
					Name: "alice",
					Type: types.PrincipalTypeUser,
				},
			},
			groupMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/alice": {
					"arn:aws:iam::123456789012:group/Developers",
				},
			},
			wantMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/alice": {
					"arn:aws:iam::123456789012:group/Developers",
				},
			},
		},
		{
			name: "Single user in multiple groups",
			users: []*types.Principal{
				{
					ARN:  "arn:aws:iam::123456789012:user/bob",
					Name: "bob",
					Type: types.PrincipalTypeUser,
				},
			},
			groupMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/bob": {
					"arn:aws:iam::123456789012:group/Developers",
					"arn:aws:iam::123456789012:group/Admins",
				},
			},
			wantMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/bob": {
					"arn:aws:iam::123456789012:group/Developers",
					"arn:aws:iam::123456789012:group/Admins",
				},
			},
		},
		{
			name: "Multiple users in different groups",
			users: []*types.Principal{
				{
					ARN:  "arn:aws:iam::123456789012:user/alice",
					Name: "alice",
					Type: types.PrincipalTypeUser,
				},
				{
					ARN:  "arn:aws:iam::123456789012:user/bob",
					Name: "bob",
					Type: types.PrincipalTypeUser,
				},
			},
			groupMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/alice": {
					"arn:aws:iam::123456789012:group/Developers",
				},
				"arn:aws:iam::123456789012:user/bob": {
					"arn:aws:iam::123456789012:group/Admins",
				},
			},
			wantMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/alice": {
					"arn:aws:iam::123456789012:group/Developers",
				},
				"arn:aws:iam::123456789012:user/bob": {
					"arn:aws:iam::123456789012:group/Admins",
				},
			},
		},
		{
			name: "User with no group memberships",
			users: []*types.Principal{
				{
					ARN:  "arn:aws:iam::123456789012:user/charlie",
					Name: "charlie",
					Type: types.PrincipalTypeUser,
				},
			},
			groupMemberships: map[string][]string{},
			wantMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/charlie": nil, // Should remain nil
			},
		},
		{
			name: "Empty users list",
			users: []*types.Principal{},
			groupMemberships: map[string][]string{
				"arn:aws:iam::123456789012:user/ghost": {
					"arn:aws:iam::123456789012:group/Ghosts",
				},
			},
			wantMemberships: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a collector (only debug flag matters for this function)
			c := &Collector{debug: false}

			// Run the function
			c.resolveGroupMemberships(tt.users, tt.groupMemberships)

			// Verify each user has correct group memberships
			for _, user := range tt.users {
				want := tt.wantMemberships[user.ARN]
				got := user.GroupMemberships

				// Check length
				if len(got) != len(want) {
					t.Errorf("User %s: got %d group memberships, want %d", user.Name, len(got), len(want))
					continue
				}

				// Check each membership
				for i, wantGroup := range want {
					if i >= len(got) || got[i] != wantGroup {
						t.Errorf("User %s: group membership[%d] = %q, want %q", user.Name, i, got[i], wantGroup)
					}
				}
			}
		})
	}
}

// TestResolveGroupMemberships_Idempotent tests that calling the function multiple times is safe
func TestResolveGroupMemberships_Idempotent(t *testing.T) {
	c := &Collector{debug: false}

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Name: "alice",
		Type: types.PrincipalTypeUser,
	}
	users := []*types.Principal{user}

	groupMemberships := map[string][]string{
		"arn:aws:iam::123456789012:user/alice": {
			"arn:aws:iam::123456789012:group/Developers",
		},
	}

	// Call twice
	c.resolveGroupMemberships(users, groupMemberships)
	firstResult := user.GroupMemberships

	c.resolveGroupMemberships(users, groupMemberships)
	secondResult := user.GroupMemberships

	// Should overwrite, not append
	if len(firstResult) != len(secondResult) {
		t.Errorf("Expected idempotent behavior, got different lengths: first=%d, second=%d", len(firstResult), len(secondResult))
	}
}

/*
NOTE: Testing Strategy for Collector Functions

The collector functions (collectGroups, getGroupInlinePolicies, etc.) make AWS SDK API calls
and are intentionally not unit tested here. Instead, they are tested through:

1. **Integration Testing**: Real AWS API calls with test accounts
2. **Manual Testing**: Documented in EXAMPLES.md for common scenarios
3. **ARN & Format Validation**: Helper functions tested in resources_test.go

This approach is chosen because:
- Mocking AWS SDK clients would require significant interface refactoring
- The functions are simple wrappers around AWS SDK calls
- Real AWS behavior is more valuable to test than mocked responses
- ARN parsing and data structure logic (the complex parts) are already tested

For contributors: When adding new collector functions, follow this pattern:
- Test pure helper functions (like resolveGroupMemberships)
- Test ARN parsing and validation
- Document manual testing steps in EXAMPLES.md
- Ensure integration tests cover the collection path
*/
