package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/pfrederiksen/aws-access-map/internal/policy"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// Collector handles fetching data from AWS APIs
type Collector struct {
	iamClient *iam.Client
	region    string
	profile   string
	debug     bool
}

// New creates a new Collector instance
func New(ctx context.Context, region, profile string, debug bool) (*Collector, error) {
	var opts []func(*config.LoadOptions) error

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	// IAM is a global service, default to us-east-1 if no region specified
	if region == "" {
		region = "us-east-1"
	}
	opts = append(opts, config.WithRegion(region))

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &Collector{
		iamClient: iam.NewFromConfig(cfg),
		region:    region,
		profile:   profile,
		debug:     debug,
	}, nil
}

// Collect fetches all relevant AWS data
func (c *Collector) Collect(ctx context.Context) (*types.CollectionResult, error) {
	result := &types.CollectionResult{
		Regions:     []string{c.region},
		CollectedAt: time.Now(),
	}

	// Get account ID
	accountID, err := c.getAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}
	result.AccountID = accountID

	// Collect IAM users
	users, err := c.collectUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect users: %w", err)
	}
	result.Principals = append(result.Principals, users...)

	// Collect IAM roles
	roles, err := c.collectRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect roles: %w", err)
	}
	result.Principals = append(result.Principals, roles...)

	// TODO: Collect groups, resource policies, SCPs, etc.

	return result, nil
}

func (c *Collector) getAccountID(ctx context.Context) (string, error) {
	output, err := c.iamClient.GetUser(ctx, &iam.GetUserInput{})
	if err != nil {
		return "", err
	}

	// Extract account ID from ARN
	if output.User != nil && output.User.Arn != nil {
		// ARN format: arn:aws:iam::123456789012:user/username
		// Parse account ID from ARN (simplified)
		return "123456789012", nil // TODO: Parse properly
	}

	return "", fmt.Errorf("unable to determine account ID")
}

func (c *Collector) collectUsers(ctx context.Context) ([]*types.Principal, error) {
	var principals []*types.Principal

	paginator := iam.NewListUsersPaginator(c.iamClient, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}

		for _, user := range output.Users {
			principal := &types.Principal{
				ARN:       *user.Arn,
				Type:      types.PrincipalTypeUser,
				Name:      *user.UserName,
				AccountID: "", // TODO: Extract from ARN
				Policies:  []types.PolicyDocument{},
			}

			// Get inline policies for this user
			policies, err := c.getUserPolicies(ctx, *user.UserName)
			if err != nil {
				return nil, fmt.Errorf("failed to get policies for user %s: %w", *user.UserName, err)
			}
			principal.Policies = policies

			principals = append(principals, principal)
		}
	}

	return principals, nil
}

func (c *Collector) collectRoles(ctx context.Context) ([]*types.Principal, error) {
	var principals []*types.Principal

	paginator := iam.NewListRolesPaginator(c.iamClient, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}

		for _, role := range output.Roles {
			principal := &types.Principal{
				ARN:       *role.Arn,
				Type:      types.PrincipalTypeRole,
				Name:      *role.RoleName,
				AccountID: "", // TODO: Extract from ARN
				Policies:  []types.PolicyDocument{},
			}

			// Parse trust policy
			if role.AssumeRolePolicyDocument != nil {
				trustPolicy, err := c.parsePolicy(*role.AssumeRolePolicyDocument)
				if err != nil {
					return nil, fmt.Errorf("failed to parse trust policy for role %s: %w", *role.RoleName, err)
				}
				principal.TrustPolicy = trustPolicy
			}

			// Get inline and attached policies for this role
			policies, err := c.getRolePolicies(ctx, *role.RoleName)
			if err != nil {
				return nil, fmt.Errorf("failed to get policies for role %s: %w", *role.RoleName, err)
			}
			principal.Policies = policies

			principals = append(principals, principal)
		}
	}

	return principals, nil
}

func (c *Collector) getUserPolicies(ctx context.Context, userName string) ([]types.PolicyDocument, error) {
	var policies []types.PolicyDocument

	// Get inline policies
	inlineOutput, err := c.iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
		UserName: &userName,
	})
	if err != nil {
		return nil, err
	}

	for _, policyName := range inlineOutput.PolicyNames {
		policyOutput, err := c.iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
			UserName:   &userName,
			PolicyName: &policyName,
		})
		if err != nil {
			return nil, err
		}

		policy, err := c.parsePolicy(*policyOutput.PolicyDocument)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policy)
	}

	// Get attached managed policies
	attachedOutput, err := c.iamClient.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: &userName,
	})
	if err != nil {
		return nil, err
	}

	for _, attached := range attachedOutput.AttachedPolicies {
		policyDoc, err := c.getManagedPolicyDocument(ctx, *attached.PolicyArn)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policyDoc)
	}

	return policies, nil
}

func (c *Collector) getRolePolicies(ctx context.Context, roleName string) ([]types.PolicyDocument, error) {
	var policies []types.PolicyDocument

	// Get inline policies
	inlineOutput, err := c.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, err
	}

	for _, policyName := range inlineOutput.PolicyNames {
		policyOutput, err := c.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			return nil, err
		}

		policy, err := c.parsePolicy(*policyOutput.PolicyDocument)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policy)
	}

	// Get attached managed policies
	attachedOutput, err := c.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, err
	}

	for _, attached := range attachedOutput.AttachedPolicies {
		policyDoc, err := c.getManagedPolicyDocument(ctx, *attached.PolicyArn)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policyDoc)
	}

	return policies, nil
}

func (c *Collector) getManagedPolicyDocument(ctx context.Context, policyArn string) (*types.PolicyDocument, error) {
	// Get the default version of the policy
	policyOutput, err := c.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return nil, err
	}

	// Get the policy document for the default version
	versionOutput, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policyOutput.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, err
	}

	return c.parsePolicy(*versionOutput.PolicyVersion.Document)
}

func (c *Collector) parsePolicy(policyDoc string) (*types.PolicyDocument, error) {
	if c.debug {
		fmt.Printf("DEBUG: Parsing policy document (first 200 chars): %s\n", policyDoc[:min(200, len(policyDoc))])
	}
	result, err := policy.Parse(policyDoc)
	if c.debug && err == nil {
		fmt.Printf("DEBUG: Parsed %d statements\n", len(result.Statements))
	}
	return result, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
