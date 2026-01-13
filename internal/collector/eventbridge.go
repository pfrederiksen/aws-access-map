package collector

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectEventBridgeResources collects EventBridge event buses and their resource policies
func (c *Collector) collectEventBridgeResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// Create EventBridge client
	eventBridgeClient := eventbridge.NewFromConfig(c.baseCfg)

	// List all event buses
	listOutput, err := eventBridgeClient.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{})
	if err != nil {
		// If we don't have EventBridge permissions, that's OK - just return empty
		if c.debug {
			fmt.Printf("DEBUG: Failed to list EventBridge event buses (may lack permissions): %v\n", err)
		}
		return resources, nil
	}

	if c.debug {
		fmt.Printf("DEBUG: Found %d EventBridge event buses\n", len(listOutput.EventBuses))
	}

	for _, bus := range listOutput.EventBuses {
		if bus.Arn == nil || bus.Name == nil {
			continue
		}

		resource := &types.Resource{
			ARN:       *bus.Arn,
			Type:      types.ResourceTypeEventBridge,
			Name:      *bus.Name,
			Region:    c.region,
			AccountID: extractAccountIDFromARN(*bus.Arn),
		}

		// Describe the event bus to get its policy
		describeOutput, err := eventBridgeClient.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{
			Name: bus.Name,
		})

		if err != nil {
			// For errors, log but continue (may be access denied)
			if c.debug {
				fmt.Printf("DEBUG: Failed to describe event bus %s: %v\n", *bus.Name, err)
			}
			resources = append(resources, resource)
			continue
		}

		// Parse the policy if it exists
		if describeOutput.Policy != nil && *describeOutput.Policy != "" {
			policyDoc, err := c.parsePolicy(*describeOutput.Policy)
			if err != nil {
				if c.debug {
					fmt.Printf("DEBUG: Failed to parse policy for event bus %s: %v\n", *bus.Name, err)
				}
				// Add resource without policy rather than failing completely
				resources = append(resources, resource)
				continue
			}
			resource.ResourcePolicy = policyDoc
		}

		resources = append(resources, resource)
	}

	return resources, nil
}
