package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectKMSResources collects KMS keys and their key policies
func (c *Collector) collectKMSResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// List KMS keys
	paginator := kms.NewListKeysPaginator(c.kmsClient, &kms.ListKeysInput{})

	keyCount := 0
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have KMS permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list KMS keys (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		for _, key := range output.Keys {
			keyCount++

			// Get key details to get ARN and account ID
			keyOutput, err := c.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				// Skip keys we can't access
				if c.debug {
					fmt.Printf("DEBUG: Failed to describe KMS key %s: %v\n", *key.KeyId, err)
				}
				continue
			}

			if keyOutput.KeyMetadata == nil {
				continue
			}

			// Skip keys that are pending deletion or disabled
			if keyOutput.KeyMetadata.KeyState != "Enabled" {
				continue
			}

			resource := &types.Resource{
				ARN:       *keyOutput.KeyMetadata.Arn,
				Type:      types.ResourceTypeKMS,
				Name:      *key.KeyId,
				Region:    c.region,
				AccountID: *keyOutput.KeyMetadata.AWSAccountId,
			}

			// Get key policy (default policy name is "default")
			policyOutput, err := c.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId:      key.KeyId,
				PolicyName: aws.String("default"),
			})

			if err != nil {
				// Log but continue - key may not have a custom policy
				if c.debug {
					fmt.Printf("DEBUG: Failed to get policy for KMS key %s: %v\n", *key.KeyId, err)
				}
				resources = append(resources, resource)
				continue
			}

			// Parse the policy
			if policyOutput.Policy != nil {
				policyDoc, err := c.parsePolicy(*policyOutput.Policy)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for KMS key %s: %v\n", *key.KeyId, err)
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
		fmt.Printf("DEBUG: Found %d KMS keys\n", keyCount)
	}

	return resources, nil
}
