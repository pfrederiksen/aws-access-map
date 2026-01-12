package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectSQSResources collects SQS queues and their resource policies
func (c *Collector) collectSQSResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// List queues
	paginator := sqs.NewListQueuesPaginator(c.sqsClient, &sqs.ListQueuesInput{})

	queueCount := 0
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have SQS permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list SQS queues (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		for _, queueURL := range output.QueueUrls {
			queueCount++

			// Get queue attributes including ARN and Policy
			attrs, err := c.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: &queueURL,
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNameQueueArn,
					sqstypes.QueueAttributeNamePolicy,
				},
			})

			if err != nil {
				if c.debug {
					fmt.Printf("DEBUG: Failed to get attributes for SQS queue %s: %v\n", queueURL, err)
				}
				continue
			}

			queueARN, hasARN := attrs.Attributes["QueueArn"]
			if !hasARN {
				continue
			}

			// Extract queue name from URL
			queueName := extractQueueNameFromURL(queueURL)

			resource := &types.Resource{
				ARN:    queueARN,
				Type:   types.ResourceTypeSQS,
				Name:   queueName,
				Region: c.region,
			}

			// Parse policy if present
			if policyStr, ok := attrs.Attributes["Policy"]; ok && policyStr != "" {
				policyDoc, err := c.parsePolicy(policyStr)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for SQS queue %s: %v\n", queueName, err)
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
		fmt.Printf("DEBUG: Found %d SQS queues\n", queueCount)
	}

	return resources, nil
}

// extractQueueNameFromURL extracts the queue name from an SQS queue URL
// Example: https://sqs.us-east-1.amazonaws.com/123456789012/my-queue -> my-queue
func extractQueueNameFromURL(queueURL string) string {
	parts := strings.Split(queueURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return queueURL
}
