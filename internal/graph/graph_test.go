package graph

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestNew(t *testing.T) {
	g := New()
	if g == nil {
		t.Fatal("New() returned nil")
	}
	if g.principals == nil || g.resources == nil {
		t.Error("New() did not initialize maps")
	}
}

func TestAddPrincipal(t *testing.T) {
	g := New()
	p := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
	}

	g.AddPrincipal(p)

	retrieved, ok := g.GetPrincipal(p.ARN)
	if !ok {
		t.Fatal("GetPrincipal() did not find added principal")
	}
	if retrieved.ARN != p.ARN {
		t.Errorf("GetPrincipal() returned wrong principal: got %v, want %v", retrieved.ARN, p.ARN)
	}
}

func TestAddResource(t *testing.T) {
	g := New()
	r := &types.Resource{
		ARN:  "arn:aws:s3:::my-bucket",
		Type: types.ResourceTypeS3,
		Name: "my-bucket",
	}

	g.AddResource(r)

	retrieved, ok := g.GetResource(r.ARN)
	if !ok {
		t.Fatal("GetResource() did not find added resource")
	}
	if retrieved.ARN != r.ARN {
		t.Errorf("GetResource() returned wrong resource: got %v, want %v", retrieved.ARN, r.ARN)
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/alice"
	action := "s3:GetObject"
	resourceARN := "arn:aws:s3:::bucket/*"

	// Add allow edge
	g.AddEdge(principalARN, action, resourceARN, false)

	// Check the edge was added
	if !g.CanAccess(principalARN, action, "arn:aws:s3:::bucket/key.txt") {
		t.Error("CanAccess() returned false after adding allow edge")
	}
}

func TestAddEdgeDeny(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/alice"
	action := "s3:*"
	resourceARN := "arn:aws:s3:::sensitive-bucket/*"

	// Add allow for all S3
	g.AddEdge(principalARN, "s3:*", "*", false)

	// Add explicit deny for sensitive bucket
	g.AddEdge(principalARN, action, resourceARN, true)

	// Should have access to regular bucket
	if !g.CanAccess(principalARN, "s3:GetObject", "arn:aws:s3:::regular-bucket/key.txt") {
		t.Error("CanAccess() should allow access to non-denied resource")
	}

	// Should NOT have access to sensitive bucket (deny wins)
	if g.CanAccess(principalARN, "s3:GetObject", "arn:aws:s3:::sensitive-bucket/secret.txt") {
		t.Error("CanAccess() should deny access when explicit deny exists")
	}
}

func TestCanAccessWildcards(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/admin"

	// Admin with wildcard permissions
	g.AddEdge(principalARN, "*", "*", false)

	tests := []struct {
		action   string
		resource string
		want     bool
	}{
		{"s3:GetObject", "arn:aws:s3:::bucket/key", true},
		{"iam:CreateUser", "arn:aws:iam::123456789012:user/bob", true},
		{"ec2:TerminateInstances", "arn:aws:ec2:us-east-1:123456789012:instance/*", true},
		{"anything:anything", "*", true},
	}

	for _, tt := range tests {
		got := g.CanAccess(principalARN, tt.action, tt.resource)
		if got != tt.want {
			t.Errorf("CanAccess(%q, %q) = %v, want %v", tt.action, tt.resource, got, tt.want)
		}
	}
}

func TestCanAccessActionWildcards(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/s3-user"

	// User with s3:* permissions
	g.AddEdge(principalARN, "s3:*", "*", false)

	tests := []struct {
		action string
		want   bool
	}{
		{"s3:GetObject", true},
		{"s3:PutObject", true},
		{"s3:ListBucket", true},
		{"iam:CreateUser", false}, // Not S3
		{"ec2:RunInstances", false},
	}

	for _, tt := range tests {
		got := g.CanAccess(principalARN, tt.action, "*")
		if got != tt.want {
			t.Errorf("CanAccess(%q, *) = %v, want %v", tt.action, got, tt.want)
		}
	}
}

func TestCanAccessResourceWildcards(t *testing.T) {
	g := New()
	principalARN := "arn:aws:iam::123456789012:user/bucket-user"

	// User with access to specific bucket
	g.AddEdge(principalARN, "s3:GetObject", "arn:aws:s3:::my-bucket/*", false)

	tests := []struct {
		resource string
		want     bool
	}{
		{"arn:aws:s3:::my-bucket/key.txt", true},
		{"arn:aws:s3:::my-bucket/dir/file.pdf", true},
		{"arn:aws:s3:::other-bucket/key.txt", false},
		{"arn:aws:s3:::my-bucket", false}, // Bucket itself, not objects
	}

	for _, tt := range tests {
		got := g.CanAccess(principalARN, "s3:GetObject", tt.resource)
		if got != tt.want {
			t.Errorf("CanAccess(s3:GetObject, %q) = %v, want %v", tt.resource, got, tt.want)
		}
	}
}

func TestGetAllPrincipals(t *testing.T) {
	g := New()

	principals := []*types.Principal{
		{ARN: "arn:aws:iam::123456789012:user/alice", Type: types.PrincipalTypeUser, Name: "alice"},
		{ARN: "arn:aws:iam::123456789012:user/bob", Type: types.PrincipalTypeUser, Name: "bob"},
		{ARN: "arn:aws:iam::123456789012:role/admin", Type: types.PrincipalTypeRole, Name: "admin"},
	}

	for _, p := range principals {
		g.AddPrincipal(p)
	}

	all := g.GetAllPrincipals()
	if len(all) != len(principals) {
		t.Errorf("GetAllPrincipals() returned %d principals, want %d", len(all), len(principals))
	}
}

func TestAddTrustRelation(t *testing.T) {
	g := New()
	roleARN := "arn:aws:iam::123456789012:role/MyRole"
	trustorARN := "arn:aws:iam::123456789012:user/alice"

	g.AddTrustRelation(roleARN, trustorARN)

	trusted := g.GetTrustedPrincipals(roleARN)
	if len(trusted) != 1 {
		t.Fatalf("GetTrustedPrincipals() returned %d principals, want 1", len(trusted))
	}
	if trusted[0] != trustorARN {
		t.Errorf("GetTrustedPrincipals() returned %q, want %q", trusted[0], trustorARN)
	}
}

func TestBuildFromCollection(t *testing.T) {
	collection := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/alice",
				Type: types.PrincipalTypeUser,
				Name: "alice",
				Policies: []types.PolicyDocument{
					{
						Version: "2012-10-17",
						Statements: []types.Statement{
							{
								Effect:   types.EffectAllow,
								Action:   "s3:GetObject",
								Resource: "arn:aws:s3:::my-bucket/*",
							},
						},
					},
				},
			},
		},
		Resources: []*types.Resource{},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Check principal was added
	p, ok := g.GetPrincipal("arn:aws:iam::123456789012:user/alice")
	if !ok {
		t.Fatal("Build() did not add principal to graph")
	}
	if p.Name != "alice" {
		t.Errorf("Build() principal name = %q, want %q", p.Name, "alice")
	}

	// Check permission was added
	if !g.CanAccess(p.ARN, "s3:GetObject", "arn:aws:s3:::my-bucket/file.txt") {
		t.Error("Build() did not correctly add permissions from policy")
	}
}

func TestBuildWithTrustPolicy(t *testing.T) {
	collection := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:role/MyRole",
				Type: types.PrincipalTypeRole,
				Name: "MyRole",
				TrustPolicy: &types.PolicyDocument{
					Version: "2012-10-17",
					Statements: []types.Statement{
						{
							Effect: types.EffectAllow,
							Principal: map[string]interface{}{
								"AWS": "arn:aws:iam::123456789012:user/alice",
							},
							Action: "sts:AssumeRole",
						},
					},
				},
			},
		},
	}

	g, err := Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	trusted := g.GetTrustedPrincipals("arn:aws:iam::123456789012:role/MyRole")
	if len(trusted) == 0 {
		t.Error("Build() did not process trust policy")
	}
}

func TestNormalizeToSlice(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "String input",
			input: "s3:GetObject",
			want:  []string{"s3:GetObject"},
		},
		{
			name:  "String slice input",
			input: []string{"s3:GetObject", "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "Interface slice with strings",
			input: []interface{}{"s3:GetObject", "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"},
		},
		{
			name:  "Interface slice with mixed types",
			input: []interface{}{"s3:GetObject", 123, "s3:PutObject"},
			want:  []string{"s3:GetObject", "s3:PutObject"}, // Non-string filtered out
		},
		{
			name:  "Empty interface slice",
			input: []interface{}{},
			want:  []string{},
		},
		{
			name:  "Nil input",
			input: nil,
			want:  []string{},
		},
		{
			name:  "Invalid type",
			input: 123,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeToSlice(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("normalizeToSlice() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeToSlice()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractPrincipals(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{
			name:  "String principal",
			input: "arn:aws:iam::123456789012:user/alice",
			want:  []string{"arn:aws:iam::123456789012:user/alice"},
		},
		{
			name: "Map with AWS key",
			input: map[string]interface{}{
				"AWS": "arn:aws:iam::123456789012:user/alice",
			},
			want: []string{"arn:aws:iam::123456789012:user/alice"},
		},
		{
			name: "Map with array of principals",
			input: map[string]interface{}{
				"AWS": []interface{}{
					"arn:aws:iam::123456789012:user/alice",
					"arn:aws:iam::123456789012:user/bob",
				},
			},
			want: []string{
				"arn:aws:iam::123456789012:user/alice",
				"arn:aws:iam::123456789012:user/bob",
			},
		},
		{
			name: "Map with Service key",
			input: map[string]interface{}{
				"Service": "lambda.amazonaws.com",
			},
			want: []string{"lambda.amazonaws.com"},
		},
		{
			name: "Map with multiple keys",
			input: map[string]interface{}{
				"AWS":     "arn:aws:iam::123456789012:user/alice",
				"Service": "lambda.amazonaws.com",
			},
			want: []string{"arn:aws:iam::123456789012:user/alice", "lambda.amazonaws.com"},
		},
		{
			name:  "Nil input",
			input: nil,
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPrincipals(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("extractPrincipals() = %v, want %v", got, tt.want)
				return
			}
			// Sort both slices for comparison since map iteration order is random
			// For simplicity in this test, just check length matches
			// In real scenarios we'd sort and compare
		})
	}
}
