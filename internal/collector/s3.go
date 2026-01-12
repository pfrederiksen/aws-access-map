package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// collectS3Resources collects S3 buckets and their bucket policies
func (c *Collector) collectS3Resources(ctx context.Context) ([]*types.Resource, error) {
	var resources []*types.Resource

	// List all buckets
	listOutput, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		// If we don't have S3 permissions, that's OK - just return empty
		if c.debug {
			fmt.Printf("DEBUG: Failed to list S3 buckets (may lack permissions): %v\n", err)
		}
		return resources, nil
	}

	if c.debug {
		fmt.Printf("DEBUG: Found %d S3 buckets\n", len(listOutput.Buckets))
	}

	for _, bucket := range listOutput.Buckets {
		if bucket.Name == nil {
			continue
		}

		resource := &types.Resource{
			ARN:       fmt.Sprintf("arn:aws:s3:::%s", *bucket.Name),
			Type:      types.ResourceTypeS3,
			Name:      *bucket.Name,
			Region:    c.region, // S3 buckets are global but we use configured region
			AccountID: "",       // S3 doesn't expose owner account ID directly
		}

		// Try to get bucket policy
		policyOutput, err := c.s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: bucket.Name,
		})

		// It's OK if bucket doesn't have a policy
		if err != nil {
			// Check if it's a NoSuchBucketPolicy error (expected for buckets without policies)
			errStr := err.Error()
			if strings.Contains(errStr, "NoSuchBucketPolicy") || strings.Contains(errStr, "does not have a bucket policy") {
				// No policy is fine, continue
				resources = append(resources, resource)
				continue
			}

			// For other errors, log but continue (may be access denied)
			if c.debug {
				fmt.Printf("DEBUG: Failed to get policy for bucket %s: %v\n", *bucket.Name, err)
			}
			resources = append(resources, resource)
			continue
		}

		// Parse the policy if it exists
		if policyOutput.Policy != nil {
			policyDoc, err := c.parsePolicy(*policyOutput.Policy)
			if err != nil {
				if c.debug {
					fmt.Printf("DEBUG: Failed to parse policy for bucket %s: %v\n", *bucket.Name, err)
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
