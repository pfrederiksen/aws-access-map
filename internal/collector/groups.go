package collector

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/pfrederiksen/aws-access-map/internal/policy"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectGroups collects IAM groups with their policies and members
func (c *Collector) collectGroups(ctx context.Context) ([]*types.Principal, map[string][]string, error) {
	if c.debug {
		fmt.Fprintln(os.Stderr, "DEBUG: Collecting IAM groups...")
	}

	var groups []*types.Principal
	groupMemberships := make(map[string][]string) // userARN -> []groupARN

	// List all groups with pagination
	paginator := iam.NewListGroupsPaginator(c.iamClient, &iam.ListGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list groups: %w", err)
		}

		for _, group := range page.Groups {
			groupARN := *group.Arn
			groupName := *group.GroupName

			if c.debug {
				fmt.Fprintf(os.Stderr, "DEBUG: Processing group: %s\n", groupName)
			}

			// Create principal for this group
			principal := &types.Principal{
				ARN:       groupARN,
				Type:      types.PrincipalTypeGroup,
				Name:      groupName,
				AccountID: extractAccountIDFromARN(groupARN),
				Policies:  []types.PolicyDocument{},
			}

			// Collect inline policies
			inlinePolicies, err := c.getGroupInlinePolicies(ctx, groupName)
			if err != nil {
				if c.debug {
					fmt.Fprintf(os.Stderr, "DEBUG: Failed to get inline policies for group %s: %v\n", groupName, err)
				}
			} else {
				principal.Policies = append(principal.Policies, inlinePolicies...)
			}

			// Collect attached managed policies
			attachedPolicies, err := c.getGroupAttachedPolicies(ctx, groupName)
			if err != nil {
				if c.debug {
					fmt.Fprintf(os.Stderr, "DEBUG: Failed to get attached policies for group %s: %v\n", groupName, err)
				}
			} else {
				principal.Policies = append(principal.Policies, attachedPolicies...)
			}

			// Get group members
			members, err := c.getGroupMembers(ctx, groupName)
			if err != nil {
				if c.debug {
					fmt.Fprintf(os.Stderr, "DEBUG: Failed to get members for group %s: %v\n", groupName, err)
				}
			} else {
				// Build membership map: userARN -> []groupARN
				for _, memberARN := range members {
					groupMemberships[memberARN] = append(groupMemberships[memberARN], groupARN)
				}
			}

			groups = append(groups, principal)
		}
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "DEBUG: Collected %d groups\n", len(groups))
	}

	return groups, groupMemberships, nil
}

// getGroupInlinePolicies fetches inline policies for a group
func (c *Collector) getGroupInlinePolicies(ctx context.Context, groupName string) ([]types.PolicyDocument, error) {
	var policies []types.PolicyDocument

	// List inline policy names
	listOutput, err := c.iamClient.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{
		GroupName: &groupName,
	})
	if err != nil {
		return nil, err
	}

	// Fetch each inline policy document
	for _, policyName := range listOutput.PolicyNames {
		policyOutput, err := c.iamClient.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
			GroupName:  &groupName,
			PolicyName: &policyName,
		})
		if err != nil {
			if c.debug {
				fmt.Fprintf(os.Stderr, "DEBUG: Failed to get inline policy %s for group %s: %v\n", policyName, groupName, err)
			}
			continue
		}

		if policyOutput.PolicyDocument != nil {
			policyDoc, err := policy.Parse(*policyOutput.PolicyDocument)
			if err != nil {
				if c.debug {
					fmt.Fprintf(os.Stderr, "DEBUG: Failed to parse inline policy %s: %v\n", policyName, err)
				}
				continue
			}
			policies = append(policies, *policyDoc)
		}
	}

	return policies, nil
}

// getGroupAttachedPolicies fetches managed policies attached to a group
func (c *Collector) getGroupAttachedPolicies(ctx context.Context, groupName string) ([]types.PolicyDocument, error) {
	var policies []types.PolicyDocument

	// List attached managed policies
	listOutput, err := c.iamClient.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{
		GroupName: &groupName,
	})
	if err != nil {
		return nil, err
	}

	// Fetch each managed policy document
	for _, attachedPolicy := range listOutput.AttachedPolicies {
		if attachedPolicy.PolicyArn == nil {
			continue
		}

		policyDoc, err := c.getManagedPolicyDocument(ctx, *attachedPolicy.PolicyArn)
		if err != nil {
			if c.debug {
				fmt.Fprintf(os.Stderr, "DEBUG: Failed to get managed policy %s: %v\n", *attachedPolicy.PolicyArn, err)
			}
			continue
		}

		if policyDoc != nil {
			policies = append(policies, *policyDoc)
		}
	}

	return policies, nil
}

// getGroupMembers fetches the list of users in a group
func (c *Collector) getGroupMembers(ctx context.Context, groupName string) ([]string, error) {
	var memberARNs []string

	// GetGroup returns group details including members
	output, err := c.iamClient.GetGroup(ctx, &iam.GetGroupInput{
		GroupName: &groupName,
	})
	if err != nil {
		return nil, err
	}

	// Extract user ARNs from group members
	for _, user := range output.Users {
		if user.Arn != nil {
			memberARNs = append(memberARNs, *user.Arn)
		}
	}

	return memberARNs, nil
}

// resolveGroupMemberships updates user principals with their group memberships
func (c *Collector) resolveGroupMemberships(users []*types.Principal, groupMemberships map[string][]string) {
	for _, user := range users {
		if memberships, exists := groupMemberships[user.ARN]; exists {
			user.GroupMemberships = memberships
			if c.debug {
				fmt.Fprintf(os.Stderr, "DEBUG: User %s is in %d groups\n", user.Name, len(memberships))
			}
		}
	}
}
