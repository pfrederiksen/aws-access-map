package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectAPIGatewayResources collects API Gateway REST APIs and their resource policies
func (c *Collector) collectAPIGatewayResources(ctx context.Context, accountID string) ([]*types.Resource, error) {
	var resources []*types.Resource

	// Create API Gateway client
	apiGWClient := apigateway.NewFromConfig(c.baseCfg)

	// List all REST APIs with pagination
	paginator := apigateway.NewGetRestApisPaginator(apiGWClient, &apigateway.GetRestApisInput{})

	apiCount := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have API Gateway permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list API Gateway REST APIs (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		apiCount += len(page.Items)

		for _, api := range page.Items {
			if api.Id == nil || api.Name == nil {
				continue
			}

			// API Gateway ARN format for execution: arn:aws:execute-api:region:account:api-id/*/*
			// This represents all stages, methods, and paths
			arn := fmt.Sprintf("arn:aws:execute-api:%s:%s:%s/*/*", c.region, accountID, *api.Id)

			resource := &types.Resource{
				ARN:       arn,
				Type:      types.ResourceTypeAPIGateway,
				Name:      *api.Name,
				Region:    c.region,
				AccountID: accountID,
			}

			// API Gateway resource policy is embedded in the API details
			// We already have it from GetRestApis, but it's in the Policy field
			if api.Policy != nil && *api.Policy != "" {
				policyDoc, err := c.parsePolicy(*api.Policy)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for API Gateway %s: %v\n", *api.Name, err)
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
		fmt.Printf("DEBUG: Found %d API Gateway REST APIs\n", apiCount)
	}

	return resources, nil
}
