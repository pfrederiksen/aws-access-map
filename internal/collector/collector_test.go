package collector

import (
	"testing"
)

// TestExtractAccountIDFromARN tests the account ID extraction from ARN
func TestExtractAccountIDFromARN(t *testing.T) {
	tests := []struct {
		name      string
		arn       string
		wantAccID string
	}{
		{
			name:      "User ARN",
			arn:       "arn:aws:iam::123456789012:user/alice",
			wantAccID: "123456789012",
		},
		{
			name:      "Role ARN",
			arn:       "arn:aws:iam::987654321098:role/AdminRole",
			wantAccID: "987654321098",
		},
		{
			name:      "S3 bucket ARN (no account ID)",
			arn:       "arn:aws:s3:::my-bucket",
			wantAccID: "",
		},
		{
			name:      "KMS key ARN",
			arn:       "arn:aws:kms:us-east-1:111122223333:key/abc-123",
			wantAccID: "111122223333",
		},
		{
			name:      "Lambda function ARN",
			arn:       "arn:aws:lambda:us-west-2:444455556666:function:my-function",
			wantAccID: "444455556666",
		},
		{
			name:      "Invalid ARN (too short)",
			arn:       "arn:aws:iam",
			wantAccID: "",
		},
		{
			name:      "Empty ARN",
			arn:       "",
			wantAccID: "",
		},
		{
			name:      "Malformed ARN",
			arn:       "not-an-arn",
			wantAccID: "",
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

// TestExtractAccountIDFromARN_EdgeCases tests edge cases
func TestExtractAccountIDFromARN_EdgeCases(t *testing.T) {
	// Test with colons in resource path
	arn := "arn:aws:sns:us-east-1:123456789012:my:topic:name"
	got := extractAccountIDFromARN(arn)
	want := "123456789012"
	if got != want {
		t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", arn, got, want)
	}

	// Test with empty account ID field (like S3)
	arn = "arn:aws:s3:::bucket-name"
	got = extractAccountIDFromARN(arn)
	want = ""
	if got != want {
		t.Errorf("extractAccountIDFromARN(%q) = %q, want %q", arn, got, want)
	}
}
