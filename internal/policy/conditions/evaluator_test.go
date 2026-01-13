package conditions

import (
	"testing"
	"time"
)

func TestEvaluate_EmptyCondition(t *testing.T) {
	ctx := NewDefaultContext()
	condition := map[string]map[string]interface{}{}

	result, err := Evaluate(condition, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("empty condition should always pass")
	}
}

func TestEvaluate_NilContext(t *testing.T) {
	// Should use default permissive context
	condition := map[string]map[string]interface{}{
		"Bool": {
			"aws:SecureTransport": true,
		},
	}

	result, err := Evaluate(condition, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("should use default context when nil")
	}
}

func TestEvaluate_MultipleOperators(t *testing.T) {
	ctx := &EvaluationContext{
		PrincipalOrgID:   "o-123456",
		MFAAuthenticated: true,
	}

	condition := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:PrincipalOrgID": "o-123456",
		},
		"Bool": {
			"aws:MultiFactorAuthPresent": true,
		},
	}

	result, err := Evaluate(condition, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result {
		t.Error("all conditions should pass")
	}
}

func TestEvaluate_MultipleOperators_OneFails(t *testing.T) {
	ctx := &EvaluationContext{
		PrincipalOrgID:   "o-123456",
		MFAAuthenticated: false, // This will cause failure
	}

	condition := map[string]map[string]interface{}{
		"StringEquals": {
			"aws:PrincipalOrgID": "o-123456",
		},
		"Bool": {
			"aws:MultiFactorAuthPresent": true, // Expects true, but ctx has false
		},
	}

	result, err := Evaluate(condition, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("condition should fail when any operator fails")
	}
}

func TestEvaluateStringEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "Match principal org ID",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-123456"},
			want: true,
		},
		{
			name: "Mismatch principal org ID",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-999999"},
			want: false,
		},
		{
			name: "Missing context value",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{}, // No PrincipalOrgID set
			want: false,
		},
		{
			name: "Match principal ARN",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice",
			},
			ctx:  &EvaluationContext{PrincipalARN: "arn:aws:iam::123456789012:user/alice"},
			want: true,
		},
		{
			name: "Case sensitive - no match",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "O-123456", // Capital O
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-123456"}, // Lowercase o
			want: false,
		},
		{
			name: "Invalid operand type",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": 12345, // Not a string
			},
			ctx:     &EvaluationContext{PrincipalOrgID: "o-123456"},
			want:    false,
			wantErr: true,
		},
		{
			name: "Principal tag match",
			operands: map[string]interface{}{
				"aws:PrincipalTag/Environment": "production",
			},
			ctx: &EvaluationContext{
				PrincipalTags: map[string]string{"Environment": "production"},
			},
			want: true,
		},
		{
			name: "Resource tag match",
			operands: map[string]interface{}{
				"aws:ResourceTag/Department": "engineering",
			},
			ctx: &EvaluationContext{
				ResourceTags: map[string]string{"Department": "engineering"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateStringEquals(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateStringEquals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateStringEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateStringNotEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Different values - pass",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-999999"},
			want: true,
		},
		{
			name: "Same values - fail",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-123456"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateStringNotEquals(tt.operands, tt.ctx)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateStringNotEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateStringLike(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Exact match",
			operands: map[string]interface{}{
				"aws:PrincipalOrgID": "o-123456",
			},
			ctx:  &EvaluationContext{PrincipalOrgID: "o-123456"},
			want: true,
		},
		{
			name: "Wildcard prefix",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::*:user/alice",
			},
			ctx:  &EvaluationContext{PrincipalARN: "arn:aws:iam::123456789012:user/alice"},
			want: true,
		},
		{
			name: "Wildcard suffix",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/*",
			},
			ctx:  &EvaluationContext{PrincipalARN: "arn:aws:iam::123456789012:user/alice"},
			want: true,
		},
		{
			name: "Wildcard middle",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:*:user/alice",
			},
			ctx:  &EvaluationContext{PrincipalARN: "arn:aws:iam::123456789012:user/alice"},
			want: true,
		},
		{
			name: "No match",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::*:role/alice",
			},
			ctx:  &EvaluationContext{PrincipalARN: "arn:aws:iam::123456789012:user/alice"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateStringLike(tt.operands, tt.ctx)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateStringLike() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateBool(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "MFA true - match",
			operands: map[string]interface{}{
				"aws:MultiFactorAuthPresent": true,
			},
			ctx:  &EvaluationContext{MFAAuthenticated: true},
			want: true,
		},
		{
			name: "MFA true as string - match",
			operands: map[string]interface{}{
				"aws:MultiFactorAuthPresent": "true",
			},
			ctx:  &EvaluationContext{MFAAuthenticated: true},
			want: true,
		},
		{
			name: "MFA false - match",
			operands: map[string]interface{}{
				"aws:MultiFactorAuthPresent": false,
			},
			ctx:  &EvaluationContext{MFAAuthenticated: false},
			want: true,
		},
		{
			name: "MFA mismatch",
			operands: map[string]interface{}{
				"aws:MultiFactorAuthPresent": true,
			},
			ctx:  &EvaluationContext{MFAAuthenticated: false},
			want: false,
		},
		{
			name: "SecureTransport true",
			operands: map[string]interface{}{
				"aws:SecureTransport": true,
			},
			ctx:  &EvaluationContext{SecureTransport: true},
			want: true,
		},
		{
			name: "SecureTransport false",
			operands: map[string]interface{}{
				"aws:SecureTransport": false,
			},
			ctx:  &EvaluationContext{SecureTransport: false},
			want: true,
		},
		{
			name: "Invalid type",
			operands: map[string]interface{}{
				"aws:MultiFactorAuthPresent": 123,
			},
			ctx:     &EvaluationContext{MFAAuthenticated: true},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateBool(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateBool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "IP in CIDR block",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.0/24",
			},
			ctx:  &EvaluationContext{SourceIP: "203.0.113.50"},
			want: true,
		},
		{
			name: "IP not in CIDR block",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.0/24",
			},
			ctx:  &EvaluationContext{SourceIP: "192.0.2.1"},
			want: false,
		},
		{
			name: "Exact IP match (auto /32)",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.50",
			},
			ctx:  &EvaluationContext{SourceIP: "203.0.113.50"},
			want: true,
		},
		{
			name: "Exact IP mismatch",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.50",
			},
			ctx:  &EvaluationContext{SourceIP: "203.0.113.51"},
			want: false,
		},
		{
			name: "Private IP in 10.0.0.0/8",
			operands: map[string]interface{}{
				"aws:SourceIp": "10.0.0.0/8",
			},
			ctx:  &EvaluationContext{SourceIP: "10.255.255.255"},
			want: true,
		},
		{
			name: "IP outside private range",
			operands: map[string]interface{}{
				"aws:SourceIp": "10.0.0.0/8",
			},
			ctx:  &EvaluationContext{SourceIP: "11.0.0.1"},
			want: false,
		},
		{
			name: "Missing source IP",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.0/24",
			},
			ctx:  &EvaluationContext{}, // No SourceIP
			want: false,
		},
		{
			name: "Invalid CIDR",
			operands: map[string]interface{}{
				"aws:SourceIp": "not-a-cidr",
			},
			ctx:     &EvaluationContext{SourceIP: "203.0.113.50"},
			want:    false,
			wantErr: true,
		},
		{
			name: "Invalid source IP in context",
			operands: map[string]interface{}{
				"aws:SourceIp": "203.0.113.0/24",
			},
			ctx:     &EvaluationContext{SourceIP: "invalid-ip"},
			want:    false,
			wantErr: true,
		},
		{
			name: "Unsupported key",
			operands: map[string]interface{}{
				"aws:SomeOtherKey": "value",
			},
			ctx:     &EvaluationContext{SourceIP: "203.0.113.50"},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateIPAddress(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateIPAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateIPAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern string
		text    string
		want    bool
	}{
		{"exact", "exact", true},
		{"exact", "nomatch", false},
		{"*", "anything", true},
		{"prefix*", "prefixsuffix", true},
		{"prefix*", "nomatch", false},
		{"*suffix", "prefixsuffix", true},
		{"*suffix", "nomatch", false},
		{"pre*fix", "prefix", true},
		{"pre*fix", "preINSIDEfix", true},
		{"pre*fix", "prefixNOPE", false},
		{"arn:aws:*:user/alice", "arn:aws:iam::123456789012:user/alice", true},
		{"arn:aws:*:user/alice", "arn:aws:iam::123456789012:role/alice", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.text, func(t *testing.T) {
			got := wildcardMatch(tt.pattern, tt.text)
			if got != tt.want {
				t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.text, got, tt.want)
			}
		})
	}
}

func TestEvaluateOperator_UnsupportedOperator(t *testing.T) {
	ctx := NewDefaultContext()
	operands := map[string]interface{}{"key": "value"}

	_, err := evaluateOperator("UnsupportedOperator", operands, ctx)
	if err == nil {
		t.Error("expected error for unsupported operator")
	}
}

func TestEvaluateOperator_NotImplemented(t *testing.T) {
	ctx := NewDefaultContext()
	operands := map[string]interface{}{"key": "value"}

	notImplemented := []string{
		// All operators now implemented
	}

	for _, op := range notImplemented {
		t.Run(op, func(t *testing.T) {
			_, err := evaluateOperator(op, operands, ctx)
			if err == nil {
				t.Errorf("expected error for unimplemented operator: %s", op)
			}
		})
	}
}

func TestEvaluateNumericEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "Equal integers",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"s3:max-keys": 100,
				},
			},
			want: true,
		},
		{
			name: "Equal floats",
			operands: map[string]interface{}{
				"custom:value": 42.5,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"custom:value": 42.5,
				},
			},
			want: true,
		},
		{
			name: "Not equal",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"s3:max-keys": 50,
				},
			},
			want: false,
		},
		{
			name: "Missing key in context",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx:  &EvaluationContext{NumericContext: make(map[string]float64)},
			want: false,
		},
		{
			name: "String number conversion",
			operands: map[string]interface{}{
				"custom:value": "123.45",
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"custom:value": 123.45,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateNumericEquals(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateNumericEquals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateNumericEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateNumericLessThan(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Less than",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"s3:max-keys": 50,
				},
			},
			want: true,
		},
		{
			name: "Equal (not less)",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"s3:max-keys": 100,
				},
			},
			want: false,
		},
		{
			name: "Greater (not less)",
			operands: map[string]interface{}{
				"s3:max-keys": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"s3:max-keys": 150,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateNumericLessThan(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateNumericLessThan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateNumericGreaterThan(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Greater than",
			operands: map[string]interface{}{
				"ec2:InstanceCount": 10,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"ec2:InstanceCount": 20,
				},
			},
			want: true,
		},
		{
			name: "Equal (not greater)",
			operands: map[string]interface{}{
				"ec2:InstanceCount": 10,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"ec2:InstanceCount": 10,
				},
			},
			want: false,
		},
		{
			name: "Less (not greater)",
			operands: map[string]interface{}{
				"ec2:InstanceCount": 10,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"ec2:InstanceCount": 5,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateNumericGreaterThan(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateNumericGreaterThan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateNumericLessThanEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Less than",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 50,
				},
			},
			want: true,
		},
		{
			name: "Equal",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 100,
				},
			},
			want: true,
		},
		{
			name: "Greater (fails)",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 150,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateNumericLessThanEquals(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateNumericLessThanEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateNumericGreaterThanEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Greater than",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 150,
				},
			},
			want: true,
		},
		{
			name: "Equal",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 100,
				},
			},
			want: true,
		},
		{
			name: "Less (fails)",
			operands: map[string]interface{}{
				"value": 100,
			},
			ctx: &EvaluationContext{
				NumericContext: map[string]float64{
					"value": 50,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateNumericGreaterThanEquals(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateNumericGreaterThanEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    float64
		wantErr bool
	}{
		{"float64", float64(42.5), 42.5, false},
		{"float32", float32(42.5), 42.5, false},
		{"int", 42, 42.0, false},
		{"int32", int32(42), 42.0, false},
		{"int64", int64(42), 42.0, false},
		{"string number", "42.5", 42.5, false},
		{"string integer", "100", 100.0, false},
		{"invalid string", "not-a-number", 0, true},
		{"unsupported type", true, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toFloat64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("toFloat64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("toFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateDateEquals(t *testing.T) {
	baseTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "Equal times",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T12:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: true,
		},
		{
			name: "Different times",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T13:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: false,
		},
		{
			name: "Unix timestamp equal",
			operands: map[string]interface{}{
				"aws:CurrentTime": int64(1768478400), // 2026-01-15T12:00:00Z
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateDateEquals(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateDateEquals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateDateEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateDateLessThan(t *testing.T) {
	baseTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Before",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T13:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: true,
		},
		{
			name: "Equal (not less)",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T12:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: false,
		},
		{
			name: "After (not less)",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T11:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateDateLessThan(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateDateLessThan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateDateGreaterThan(t *testing.T) {
	baseTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "After",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T11:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: true,
		},
		{
			name: "Equal (not greater)",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T12:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: false,
		},
		{
			name: "Before (not greater)",
			operands: map[string]interface{}{
				"aws:CurrentTime": "2026-01-15T13:00:00Z",
			},
			ctx: &EvaluationContext{
				CurrentTime: baseTime,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateDateGreaterThan(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateDateGreaterThan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{"RFC3339", "2026-01-15T12:00:00Z", false},
		{"ISO 8601", "2026-01-15T12:00:00", false},
		{"Date only", "2026-01-15", false},
		{"Unix timestamp int64", int64(1736942400), false},
		{"Unix timestamp int", int(1736942400), false},
		{"Unix timestamp float", float64(1736942400), false},
		{"Invalid string", "not-a-date", true},
		{"Unsupported type", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTime() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateArnEquals(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
		wantErr  bool
	}{
		{
			name: "Exact match",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
		{
			name: "No match",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/bob",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: false,
		},
		{
			name: "Missing context value",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice",
			},
			ctx:  &EvaluationContext{},
			want: false,
		},
		{
			name: "Case sensitive",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/Alice",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateArnEquals(tt.operands, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateArnEquals() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("evaluateArnEquals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateArnLike(t *testing.T) {
	tests := []struct {
		name     string
		operands map[string]interface{}
		ctx      *EvaluationContext
		want     bool
	}{
		{
			name: "Exact match",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/alice",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
		{
			name: "Wildcard prefix",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::*:user/alice",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
		{
			name: "Wildcard suffix",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::123456789012:user/*",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
		{
			name: "Wildcard middle",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:*:user/alice",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
		{
			name: "No match",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "arn:aws:iam::*:user/bob",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: false,
		},
		{
			name: "Full wildcard",
			operands: map[string]interface{}{
				"aws:PrincipalArn": "*",
			},
			ctx: &EvaluationContext{
				PrincipalARN: "arn:aws:iam::123456789012:user/alice",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := evaluateArnLike(tt.operands, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateArnLike() = %v, want %v", got, tt.want)
			}
		})
	}
}
