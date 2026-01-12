package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectSecretsManagerResources collects Secrets Manager secrets and their resource policies
func (c *Collector) collectSecretsManagerResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// List secrets
	paginator := secretsmanager.NewListSecretsPaginator(c.secretsManagerClient, &secretsmanager.ListSecretsInput{})

	secretCount := 0
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have Secrets Manager permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list Secrets Manager secrets (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		for _, secret := range output.SecretList {
			if secret.ARN == nil || secret.Name == nil {
				continue
			}

			secretCount++

			resource := &types.Resource{
				ARN:    *secret.ARN,
				Type:   types.ResourceTypeSecretsManager,
				Name:   *secret.Name,
				Region: c.region,
			}

			// Get resource policy
			policyOutput, err := c.secretsManagerClient.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
				SecretId: secret.ARN,
			})

			if err != nil {
				// Log but continue - secret may not have a resource policy
				if c.debug {
					fmt.Printf("DEBUG: Failed to get resource policy for secret %s: %v\n", *secret.Name, err)
				}
				resources = append(resources, resource)
				continue
			}

			// Parse policy if present
			if policyOutput.ResourcePolicy != nil && *policyOutput.ResourcePolicy != "" {
				policyDoc, err := c.parsePolicy(*policyOutput.ResourcePolicy)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for secret %s: %v\n", *secret.Name, err)
					}
					resources = append(resources, resource)
					continue
				}
				resource.ResourcePolicy = policyDoc
			}

			resources = append(resources, resource)
		}
	}

	if c.debug {
		fmt.Printf("DEBUG: Found %d Secrets Manager secrets\n", secretCount)
	}

	return resources, nil
}
