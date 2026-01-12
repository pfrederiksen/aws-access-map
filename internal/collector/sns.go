package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectSNSResources collects SNS topics and their resource policies
func (c *Collector) collectSNSResources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// List topics
	paginator := sns.NewListTopicsPaginator(c.snsClient, &sns.ListTopicsInput{})

	topicCount := 0
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			// If we don't have SNS permissions, that's OK - just return empty
			if c.debug {
				fmt.Printf("DEBUG: Failed to list SNS topics (may lack permissions): %v\n", err)
			}
			return resources, nil
		}

		for _, topic := range output.Topics {
			if topic.TopicArn == nil {
				continue
			}

			topicCount++

			// Get topic attributes including Policy
			attrs, err := c.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: topic.TopicArn,
			})

			if err != nil {
				if c.debug {
					fmt.Printf("DEBUG: Failed to get attributes for SNS topic %s: %v\n", *topic.TopicArn, err)
				}
				continue
			}

			// Extract topic name from ARN
			topicName := extractTopicNameFromARN(*topic.TopicArn)

			resource := &types.Resource{
				ARN:    *topic.TopicArn,
				Type:   types.ResourceTypeSNS,
				Name:   topicName,
				Region: c.region,
			}

			// Parse policy if present
			if policyStr, ok := attrs.Attributes["Policy"]; ok && policyStr != "" {
				policyDoc, err := c.parsePolicy(policyStr)
				if err != nil {
					if c.debug {
						fmt.Printf("DEBUG: Failed to parse policy for SNS topic %s: %v\n", topicName, err)
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
		fmt.Printf("DEBUG: Found %d SNS topics\n", topicCount)
	}

	return resources, nil
}

// extractTopicNameFromARN extracts the topic name from an SNS topic ARN
// Example: arn:aws:sns:us-east-1:123456789012:my-topic -> my-topic
func extractTopicNameFromARN(topicARN string) string {
	parts := strings.Split(topicARN, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return topicARN
}
