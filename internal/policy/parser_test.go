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

func TestMatchesNotAction(t *testing.T) {
	tests := []struct {
		name              string
		notActionPatterns []string
		action            string
		want              bool
	}{
		// Empty NotAction - all actions allowed
		{
			name:              "Empty NotAction patterns",
			notActionPatterns: []string{},
			action:            "s3:GetObject",
			want:              true,
		},
		{
			name:              "Nil NotAction patterns",
			notActionPatterns: nil,
			action:            "s3:GetObject",
			want:              true,
		},

		// Single exact exclusion
		{
			name:              "Exclude exact action - match",
			notActionPatterns: []string{"s3:DeleteObject"},
			action:            "s3:DeleteObject",
			want:              false, // Action is excluded
		},
		{
			name:              "Exclude exact action - no match",
			notActionPatterns: []string{"s3:DeleteObject"},
			action:            "s3:GetObject",
			want:              true, // Action is NOT excluded
		},

		// Wildcard exclusions
		{
			name:              "Exclude s3:Delete* - DeleteObject excluded",
			notActionPatterns: []string{"s3:Delete*"},
			action:            "s3:DeleteObject",
			want:              false,
		},
		{
			name:              "Exclude s3:Delete* - GetObject allowed",
			notActionPatterns: []string{"s3:Delete*"},
			action:            "s3:GetObject",
			want:              true,
		},
		{
			name:              "Exclude s3:* - all s3 excluded",
			notActionPatterns: []string{"s3:*"},
			action:            "s3:GetObject",
			want:              false,
		},
		{
			name:              "Exclude s3:* - iam actions allowed",
			notActionPatterns: []string{"s3:*"},
			action:            "iam:CreateUser",
			want:              true,
		},

		// Multiple exclusions
		{
			name:              "Multiple patterns - first matches",
			notActionPatterns: []string{"s3:Delete*", "s3:Put*"},
			action:            "s3:DeleteObject",
			want:              false,
		},
		{
			name:              "Multiple patterns - second matches",
			notActionPatterns: []string{"s3:Delete*", "s3:Put*"},
			action:            "s3:PutObject",
			want:              false,
		},
		{
			name:              "Multiple patterns - no match",
			notActionPatterns: []string{"s3:Delete*", "s3:Put*"},
			action:            "s3:GetObject",
			want:              true,
		},

		// Common AWS pattern: allow all except specific actions
		{
			name:              "Allow all except iam:* - s3 allowed",
			notActionPatterns: []string{"iam:*"},
			action:            "s3:GetObject",
			want:              true,
		},
		{
			name:              "Allow all except iam:* - iam excluded",
			notActionPatterns: []string{"iam:*"},
			action:            "iam:CreateUser",
			want:              false,
		},

		// Universal wildcard exclusion (allow nothing)
		{
			name:              "Exclude * - nothing allowed",
			notActionPatterns: []string{"*"},
			action:            "s3:GetObject",
			want:              false,
		},

		// Complex patterns
		{
			name:              "Exclude iam:*User* - CreateUser excluded",
			notActionPatterns: []string{"iam:*User*"},
			action:            "iam:CreateUser",
			want:              false,
		},
		{
			name:              "Exclude iam:*User* - GetUserPolicy excluded",
			notActionPatterns: []string{"iam:*User*"},
			action:            "iam:GetUserPolicy",
			want:              false,
		},
		{
			name:              "Exclude iam:*User* - CreateRole allowed",
			notActionPatterns: []string{"iam:*User*"},
			action:            "iam:CreateRole",
			want:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesNotAction(tt.notActionPatterns, tt.action)
			if got != tt.want {
				t.Errorf("MatchesNotAction(%v, %q) = %v, want %v",
					tt.notActionPatterns, tt.action, got, tt.want)
			}
		})
	}
}

func TestMatchesNotResource(t *testing.T) {
	tests := []struct {
		name                 string
		notResourcePatterns  []string
		arn                  string
		want                 bool
	}{
		// Empty NotResource - all resources allowed
		{
			name:                "Empty NotResource patterns",
			notResourcePatterns: []string{},
			arn:                 "arn:aws:s3:::bucket/key",
			want:                true,
		},
		{
			name:                "Nil NotResource patterns",
			notResourcePatterns: nil,
			arn:                 "arn:aws:s3:::bucket/key",
			want:                true,
		},

		// Single exact exclusion
		{
			name:                "Exclude exact ARN - match",
			notResourcePatterns: []string{"arn:aws:s3:::production-bucket/*"},
			arn:                 "arn:aws:s3:::production-bucket/file.txt",
			want:                false, // Resource is excluded
		},
		{
			name:                "Exclude exact ARN - no match",
			notResourcePatterns: []string{"arn:aws:s3:::production-bucket/*"},
			arn:                 "arn:aws:s3:::dev-bucket/file.txt",
			want:                true, // Resource is NOT excluded
		},

		// Wildcard exclusions
		{
			name:                "Exclude production-* - production excluded",
			notResourcePatterns: []string{"arn:aws:s3:::production-*"},
			arn:                 "arn:aws:s3:::production-data",
			want:                false,
		},
		{
			name:                "Exclude production-* - dev allowed",
			notResourcePatterns: []string{"arn:aws:s3:::production-*"},
			arn:                 "arn:aws:s3:::dev-data",
			want:                true,
		},

		// Multiple exclusions
		{
			name:                "Multiple patterns - first matches",
			notResourcePatterns: []string{"arn:aws:s3:::production-*", "arn:aws:s3:::sensitive-*"},
			arn:                 "arn:aws:s3:::production-bucket",
			want:                false,
		},
		{
			name:                "Multiple patterns - second matches",
			notResourcePatterns: []string{"arn:aws:s3:::production-*", "arn:aws:s3:::sensitive-*"},
			arn:                 "arn:aws:s3:::sensitive-data",
			want:                false,
		},
		{
			name:                "Multiple patterns - no match",
			notResourcePatterns: []string{"arn:aws:s3:::production-*", "arn:aws:s3:::sensitive-*"},
			arn:                 "arn:aws:s3:::dev-bucket",
			want:                true,
		},

		// Common AWS pattern: allow all resources except specific bucket
		{
			name:                "Allow all except sensitive bucket - other allowed",
			notResourcePatterns: []string{"arn:aws:s3:::sensitive-bucket/*"},
			arn:                 "arn:aws:s3:::public-bucket/file.txt",
			want:                true,
		},
		{
			name:                "Allow all except sensitive bucket - sensitive excluded",
			notResourcePatterns: []string{"arn:aws:s3:::sensitive-bucket/*"},
			arn:                 "arn:aws:s3:::sensitive-bucket/secret.txt",
			want:                false,
		},

		// Universal wildcard exclusion (allow nothing)
		{
			name:                "Exclude * - nothing allowed",
			notResourcePatterns: []string{"*"},
			arn:                 "arn:aws:s3:::any-bucket/key",
			want:                false,
		},

		// Complex ARN patterns
		{
			name:                "Exclude IAM roles - role excluded",
			notResourcePatterns: []string{"arn:aws:iam::*:role/*"},
			arn:                 "arn:aws:iam::123456789012:role/MyRole",
			want:                false,
		},
		{
			name:                "Exclude IAM roles - user allowed",
			notResourcePatterns: []string{"arn:aws:iam::*:role/*"},
			arn:                 "arn:aws:iam::123456789012:user/MyUser",
			want:                true,
		},

		// Region-specific exclusions
		{
			name:                "Exclude us-east-1 KMS keys - us-east-1 excluded",
			notResourcePatterns: []string{"arn:aws:kms:us-east-1:*:key/*"},
			arn:                 "arn:aws:kms:us-east-1:123456789012:key/abc-123",
			want:                false,
		},
		{
			name:                "Exclude us-east-1 KMS keys - us-west-2 allowed",
			notResourcePatterns: []string{"arn:aws:kms:us-east-1:*:key/*"},
			arn:                 "arn:aws:kms:us-west-2:123456789012:key/abc-123",
			want:                true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesNotResource(tt.notResourcePatterns, tt.arn)
			if got != tt.want {
				t.Errorf("MatchesNotResource(%v, %q) = %v, want %v",
					tt.notResourcePatterns, tt.arn, got, tt.want)
			}
		})
	}
}
