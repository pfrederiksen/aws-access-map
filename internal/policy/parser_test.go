package policy

import "testing"

func TestMatchesAction(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		want    bool
	}{
		// Exact matches
		{"s3:GetObject", "s3:GetObject", true},
		{"s3:GetObject", "s3:PutObject", false},

		// Universal wildcard
		{"*", "s3:GetObject", true},
		{"*", "iam:CreateUser", true},
		{"*", "anything:anything", true},

		// Service wildcards
		{"s3:*", "s3:GetObject", true},
		{"s3:*", "s3:PutObject", true},
		{"s3:*", "iam:GetUser", false},

		// Prefix wildcards
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetBucketPolicy", true},
		{"s3:Get*", "s3:PutObject", false},
		{"iam:*User", "iam:CreateUser", true},
		{"iam:*User", "iam:GetUser", true},
		{"iam:*User", "iam:CreateRole", false},

		// Complex wildcards
		{"iam:*User*", "iam:CreateUser", true},
		{"iam:*User*", "iam:GetUserPolicy", true},
		{"iam:*User*", "iam:GetRole", false},

		// Case insensitivity
		{"S3:GetObject", "s3:getobject", true},
		{"s3:GETOBJECT", "S3:GetObject", true},
	}

	for _, tt := range tests {
		got := MatchesAction(tt.pattern, tt.action)
		if got != tt.want {
			t.Errorf("MatchesAction(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

func TestMatchesResource(t *testing.T) {
	tests := []struct {
		pattern string
		arn     string
		want    bool
	}{
		// Exact matches
		{"arn:aws:s3:::bucket/key", "arn:aws:s3:::bucket/key", true},
		{"arn:aws:s3:::bucket/key", "arn:aws:s3:::bucket/other", false},

		// Universal wildcard
		{"*", "arn:aws:s3:::bucket/key", true},
		{"*", "arn:aws:iam::123:role/foo", true},

		// Suffix wildcards
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/dir/key", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other/key", false},

		// Prefix wildcards
		{"arn:aws:s3:::*", "arn:aws:s3:::bucket", true},
		{"arn:aws:s3:::*", "arn:aws:s3:::other-bucket", true},
		{"arn:aws:s3:::*", "arn:aws:iam::123:user/foo", false},

		// Complex wildcards
		{"arn:aws:iam::*:role/*", "arn:aws:iam::123456:role/MyRole", true},
		{"arn:aws:iam::*:role/*", "arn:aws:iam::789:role/AnotherRole", true},
		{"arn:aws:iam::*:role/*", "arn:aws:iam::123:user/User", false},

		// Middle wildcards
		{"arn:aws:kms:us-east-1:*:key/*", "arn:aws:kms:us-east-1:123456:key/abc-123", true},
		{"arn:aws:kms:us-east-1:*:key/*", "arn:aws:kms:us-west-2:123456:key/abc-123", false},
	}

	for _, tt := range tests {
		got := MatchesResource(tt.pattern, tt.arn)
		if got != tt.want {
			t.Errorf("MatchesResource(%q, %q) = %v, want %v", tt.pattern, tt.arn, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name: "Valid policy JSON",
			input: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Effect": "Allow",
					"Action": "s3:GetObject",
					"Resource": "arn:aws:s3:::bucket/*"
				}]
			}`,
			wantErr: false,
		},
		{
			name:    "URL-encoded policy",
			input:   "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D",
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			input:   "not valid json",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := Parse(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && policy == nil {
				t.Error("Parse() returned nil policy when expecting valid policy")
			}
			if !tt.wantErr && policy.Version != "2012-10-17" {
				t.Errorf("Parse() policy.Version = %q, want %q", policy.Version, "2012-10-17")
			}
		})
	}
}

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name          string
		condition     map[string]map[string]interface{}
		wantResult    bool
		wantWarnings  int
	}{
		{
			name:         "Empty condition",
			condition:    map[string]map[string]interface{}{},
			wantResult:   true,
			wantWarnings: 0,
		},
		{
			name:         "Nil condition",
			condition:    nil,
			wantResult:   true,
			wantWarnings: 0,
		},
		{
			name: "Single condition",
			condition: map[string]map[string]interface{}{
				"StringEquals": {
					"aws:PrincipalOrgID": "o-123456",
				},
			},
			wantResult:   true,
			wantWarnings: 1,
		},
		{
			name: "Multiple conditions",
			condition: map[string]map[string]interface{}{
				"StringEquals": {
					"aws:PrincipalOrgID": "o-123456",
				},
				"IpAddress": {
					"aws:SourceIp": "203.0.113.0/24",
				},
			},
			wantResult:   true,
			wantWarnings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, warnings := EvaluateCondition(tt.condition)
			if result != tt.wantResult {
				t.Errorf("EvaluateCondition() result = %v, want %v", result, tt.wantResult)
			}
			if len(warnings) != tt.wantWarnings {
				t.Errorf("EvaluateCondition() warnings = %d, want %d", len(warnings), tt.wantWarnings)
			}
		})
	}
}
