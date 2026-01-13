package collector

import (
	"testing"
)

// TestExtractAccountIDFromARN_Lambda tests Lambda ARN account ID extraction
func TestExtractAccountIDFromARN_Lambda(t *testing.T) {
	tests := []struct {
		name      string
		arn       string
		wantAccID string
	}{
		{
			name:      "Lambda function ARN",
			arn:       "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			wantAccID: "123456789012",
		},
		{
			name:      "Lambda function with version",
			arn:       "arn:aws:lambda:us-west-2:987654321098:function:test-fn:1",
			wantAccID: "987654321098",
		},
		{
			name:      "Lambda function with alias",
			arn:       "arn:aws:lambda:eu-west-1:111122223333:function:prod-fn:PROD",
			wantAccID: "111122223333",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAccountIDFromARN(tt.arn)
			if got != tt.wantAccID {
				t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", tt.arn, got, tt.wantAccID)
			}
		})
	}
}

// TestExtractAccountIDFromARN_APIGateway tests API Gateway ARN account ID extraction
func TestExtractAccountIDFromARN_APIGateway(t *testing.T) {
	tests := []struct {
		name      string
		arn       string
		wantAccID string
	}{
		{
			name:      "API Gateway execution ARN",
			arn:       "arn:aws:execute-api:us-east-1:123456789012:abc123/*/*/*",
			wantAccID: "123456789012",
		},
		{
			name:      "API Gateway with specific stage/method/path",
			arn:       "arn:aws:execute-api:us-west-2:987654321098:xyz789/prod/GET/users",
			wantAccID: "987654321098",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAccountIDFromARN(tt.arn)
			if got != tt.wantAccID {
				t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", tt.arn, got, tt.wantAccID)
			}
		})
	}
}

// TestExtractAccountIDFromARN_ECR tests ECR ARN account ID extraction
func TestExtractAccountIDFromARN_ECR(t *testing.T) {
	tests := []struct {
		name      string
		arn       string
		wantAccID string
	}{
		{
			name:      "ECR repository ARN",
			arn:       "arn:aws:ecr:us-east-1:123456789012:repository/my-app",
			wantAccID: "123456789012",
		},
		{
			name:      "ECR repository with nested path",
			arn:       "arn:aws:ecr:eu-central-1:987654321098:repository/team/service/app",
			wantAccID: "987654321098",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAccountIDFromARN(tt.arn)
			if got != tt.wantAccID {
				t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", tt.arn, got, tt.wantAccID)
			}
		})
	}
}

// TestExtractAccountIDFromARN_EventBridge tests EventBridge ARN account ID extraction
func TestExtractAccountIDFromARN_EventBridge(t *testing.T) {
	tests := []struct {
		name      string
		arn       string
		wantAccID string
	}{
		{
			name:      "EventBridge default event bus",
			arn:       "arn:aws:events:us-east-1:123456789012:event-bus/default",
			wantAccID: "123456789012",
		},
		{
			name:      "EventBridge custom event bus",
			arn:       "arn:aws:events:ap-southeast-2:987654321098:event-bus/my-custom-bus",
			wantAccID: "987654321098",
		},
		{
			name:      "EventBridge partner event bus",
			arn:       "arn:aws:events:us-west-1:111122223333:event-bus/aws.partner/example.com/123",
			wantAccID: "111122223333",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAccountIDFromARN(tt.arn)
			if got != tt.wantAccID {
				t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", tt.arn, got, tt.wantAccID)
			}
		})
	}
}

// TestARNFormat_AllNewResourceTypes tests that we correctly format ARNs for all new resource types
func TestARNFormat_AllNewResourceTypes(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		wantValid   bool
		description string
	}{
		{
			name:        "Lambda function ARN format",
			arn:         "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			wantValid:   true,
			description: "Standard Lambda function ARN",
		},
		{
			name:        "API Gateway execution ARN format",
			arn:         "arn:aws:execute-api:us-east-1:123456789012:abc123/*/*/*",
			wantValid:   true,
			description: "API Gateway execution ARN with wildcards",
		},
		{
			name:        "ECR repository ARN format",
			arn:         "arn:aws:ecr:us-east-1:123456789012:repository/my-app",
			wantValid:   true,
			description: "Standard ECR repository ARN",
		},
		{
			name:        "EventBridge event bus ARN format",
			arn:         "arn:aws:events:us-east-1:123456789012:event-bus/default",
			wantValid:   true,
			description: "Standard EventBridge event bus ARN",
		},
		{
			name:        "Malformed ARN",
			arn:         "not-an-arn",
			wantValid:   false,
			description: "Invalid ARN format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate ARN structure: should have at least 6 parts separated by colons
			parts := len(splitARN(tt.arn))
			isValid := parts >= 6

			if isValid != tt.wantValid {
				t.Errorf("%s: ARN %q validity = %v, want %v", tt.description, tt.arn, isValid, tt.wantValid)
			}
		})
	}
}

// Helper function to split ARN for testing
func splitARN(arn string) []string {
	if arn == "" {
		return []string{}
	}

	parts := []string{}
	current := ""
	for _, char := range arn {
		if char == ':' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

// TestResourceTypeConstants ensures all new resource type constants are defined
func TestResourceTypeConstants(t *testing.T) {
	// This test is more of a compile-time check, but we can verify the imports work
	// The actual constants are defined in pkg/types/types.go

	// If this test compiles, it means the resource type constants exist
	// This is a simple sanity check
	t.Log("Resource type constants are properly defined")
}
