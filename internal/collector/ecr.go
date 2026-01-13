package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectECRResources collects ECR repositories and their resource policies
func (c *Collector) collectECRResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// Create ECR client
	ecrClient := ecr.NewFromConfig(c.baseCfg)

	// List all ECR repositories with pagination
	paginator := ecr.NewDescribeRepositoriesPaginator(ecrClient, &ecr.DescribeRepositoriesInput{})

	repoCount := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have ECR permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list ECR repositories (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		repoCount += len(page.Repositories)

		for _, repo := range page.Repositories {
			if repo.RepositoryArn == nil || repo.RepositoryName == nil {
				continue
			}

			resource := &types.Resource{
				ARN:       *repo.RepositoryArn,
				Type:      types.ResourceTypeECR,
				Name:      *repo.RepositoryName,
				Region:    c.region,
				AccountID: extractAccountIDFromARN(*repo.RepositoryArn),
			}

			// Try to get repository policy
			policyOutput, err := ecrClient.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
				RepositoryName: repo.RepositoryName,
			})

			// It's OK if repository doesn't have a policy
			if err != nil {
				// Check if it's a RepositoryPolicyNotFoundException (expected for repos without policies)
				errStr := err.Error()
				if strings.Contains(errStr, "RepositoryPolicyNotFoundException") ||
				   strings.Contains(errStr, "does not have a policy") {
					// No policy is fine, continue
					resources = append(resources, resource)
					continue
				}

				// For other errors, log but continue (may be access denied)
				if c.debug {
					fmt.Printf("DEBUG: Failed to get policy for ECR repository %s: %v\n", *repo.RepositoryName, err)
				}
				resources = append(resources, resource)
				continue
			}

			// Parse the policy if it exists
			if policyOutput.PolicyText != nil {
				policyDoc, err := c.parsePolicy(*policyOutput.PolicyText)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for ECR repository %s: %v\n", *repo.RepositoryName, err)
					}
					// Add resource without policy rather than failing completely
					resources = append(resources, resource)
					continue
				}
				resource.ResourcePolicy = policyDoc
			}

			resources = append(resources, resource)
		}
	}

	if c.debug {
		fmt.Printf("DEBUG: Found %d ECR repositories\n", repoCount)
	}

	return resources, nil
}
