package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectLambdaResources collects Lambda functions and their resource policies
func (c *Collector) collectLambdaResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// Create Lambda client
	lambdaClient := lambda.NewFromConfig(c.baseCfg)

	// List all Lambda functions with pagination
	paginator := lambda.NewListFunctionsPaginator(lambdaClient, &lambda.ListFunctionsInput{})

	functionCount := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have Lambda permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list Lambda functions (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		functionCount += len(page.Functions)

		for _, fn := range page.Functions {
			if fn.FunctionArn == nil || fn.FunctionName == nil {
				continue
			}

			resource := &types.Resource{
				ARN:       *fn.FunctionArn,
				Type:      types.ResourceTypeLambda,
				Name:      *fn.FunctionName,
				Region:    c.region,
				AccountID: extractAccountIDFromARN(*fn.FunctionArn),
			}

			// Try to get function policy
			policyOutput, err := lambdaClient.GetPolicy(ctx, &lambda.GetPolicyInput{
				FunctionName: fn.FunctionName,
			})

			// It's OK if function doesn't have a policy
			if err != nil {
				// Check if it's a ResourceNotFoundException (expected for functions without policies)
				errStr := err.Error()
				if strings.Contains(errStr, "ResourceNotFoundException") ||
				   strings.Contains(errStr, "does not have a resource policy") {
					// No policy is fine, continue
					resources = append(resources, resource)
					continue
				}

				// For other errors, log but continue (may be access denied)
				if c.debug {
					fmt.Printf("DEBUG: Failed to get policy for function %s: %v\n", *fn.FunctionName, err)
				}
				resources = append(resources, resource)
				continue
			}

			// Parse the policy if it exists
			if policyOutput.Policy != nil {
				policyDoc, err := c.parsePolicy(*policyOutput.Policy)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for function %s: %v\n", *fn.FunctionName, err)
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
		fmt.Printf("DEBUG: Found %d Lambda functions\n", functionCount)
	}

	return resources, nil
}
