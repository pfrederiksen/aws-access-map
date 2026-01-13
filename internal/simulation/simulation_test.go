package simulation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestLoadFromFile tests loading a CollectionResult from a JSON file
func TestLoadFromFile(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-data.json")

	testData := &types.CollectionResult{
		AccountID:   "123456789012",
		CollectedAt: time.Now(),
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
			},
		},
		Resources: []*types.Resource{
			{
				ARN:       "arn:aws:s3:::test-bucket",
				Type:      types.ResourceTypeS3,
				Name:      "test-bucket",
				AccountID: "123456789012",
			},
		},
	}

	// Write test data to file
	data, err := json.Marshal(testData)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	if err := os.WriteFile(testFile, data, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test loading the file
	result, err := LoadFromFile(testFile)
	if err != nil {
		t.Errorf("LoadFromFile() error = %v", err)
	}

	if result == nil {
		t.Fatal("LoadFromFile() returned nil result")
	}

	if result.AccountID != testData.AccountID {
		t.Errorf("LoadFromFile() AccountID = %s, want %s", result.AccountID, testData.AccountID)
	}

	if len(result.Principals) != 1 {
		t.Errorf("LoadFromFile() Principals count = %d, want 1", len(result.Principals))
	}

	if len(result.Resources) != 1 {
		t.Errorf("LoadFromFile() Resources count = %d, want 1", len(result.Resources))
	}
}

// TestLoadFromFile_NonExistentFile tests error handling for non-existent files
func TestLoadFromFile_NonExistentFile(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/file.json")
	if err == nil {
		t.Error("LoadFromFile() expected error for non-existent file, got nil")
	}
}

// TestLoadFromFile_InvalidJSON tests error handling for invalid JSON
func TestLoadFromFile_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "invalid.json")

	// Write invalid JSON
	if err := os.WriteFile(testFile, []byte("not valid json{"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err := LoadFromFile(testFile)
	if err == nil {
		t.Error("LoadFromFile() expected error for invalid JSON, got nil")
	}
}

// TestMergePolicyChanges_AddPrincipals tests adding new principals
func TestMergePolicyChanges_AddPrincipals(t *testing.T) {
	base := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/alice",
				Name: "alice",
			},
		},
	}

	changes := &PolicyChanges{
		AddPrincipals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/bob",
				Name: "bob",
			},
		},
	}

	result, err := MergePolicyChanges(base, changes)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Principals) != 2 {
		t.Errorf("MergePolicyChanges() Principals count = %d, want 2", len(result.Principals))
	}

	// Verify original is unchanged
	if len(base.Principals) != 1 {
		t.Errorf("MergePolicyChanges() modified original, count = %d, want 1", len(base.Principals))
	}
}

// TestMergePolicyChanges_RemovePrincipals tests removing principals
func TestMergePolicyChanges_RemovePrincipals(t *testing.T) {
	base := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/alice",
				Name: "alice",
			},
			{
				ARN:  "arn:aws:iam::123456789012:user/bob",
				Name: "bob",
			},
		},
	}

	changes := &PolicyChanges{
		RemovePrincipals: []string{"arn:aws:iam::123456789012:user/bob"},
	}

	result, err := MergePolicyChanges(base, changes)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Principals) != 1 {
		t.Errorf("MergePolicyChanges() Principals count = %d, want 1", len(result.Principals))
	}

	if result.Principals[0].Name != "alice" {
		t.Errorf("MergePolicyChanges() remaining principal = %s, want alice", result.Principals[0].Name)
	}
}

// TestMergePolicyChanges_UpdatePolicies tests updating policies for existing principals
func TestMergePolicyChanges_UpdatePolicies(t *testing.T) {
	base := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:      "arn:aws:iam::123456789012:user/alice",
				Name:     "alice",
				Policies: []types.PolicyDocument{
					{
						Version: "2012-10-17",
						Statements: []types.Statement{
							{
								Effect: types.EffectAllow,
								Action: []string{"s3:GetObject"},
							},
						},
					},
				},
			},
		},
	}

	newPolicy := types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect: types.EffectAllow,
				Action: []string{"s3:PutObject"},
			},
		},
	}

	changes := &PolicyChanges{
		UpdatePolicies: map[string][]types.PolicyDocument{
			"arn:aws:iam::123456789012:user/alice": {newPolicy},
		},
	}

	result, err := MergePolicyChanges(base, changes)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Principals[0].Policies) != 2 {
		t.Errorf("MergePolicyChanges() Policies count = %d, want 2", len(result.Principals[0].Policies))
	}
}

// TestMergePolicyChanges_AddResources tests adding new resources
func TestMergePolicyChanges_AddResources(t *testing.T) {
	base := &types.CollectionResult{
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::bucket1",
				Name: "bucket1",
			},
		},
	}

	changes := &PolicyChanges{
		AddResources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::bucket2",
				Name: "bucket2",
			},
		},
	}

	result, err := MergePolicyChanges(base, changes)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Resources) != 2 {
		t.Errorf("MergePolicyChanges() Resources count = %d, want 2", len(result.Resources))
	}
}

// TestMergePolicyChanges_RemoveResources tests removing resources
func TestMergePolicyChanges_RemoveResources(t *testing.T) {
	base := &types.CollectionResult{
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::bucket1",
				Name: "bucket1",
			},
			{
				ARN:  "arn:aws:s3:::bucket2",
				Name: "bucket2",
			},
		},
	}

	changes := &PolicyChanges{
		RemoveResources: []string{"arn:aws:s3:::bucket1"},
	}

	result, err := MergePolicyChanges(base, changes)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Resources) != 1 {
		t.Errorf("MergePolicyChanges() Resources count = %d, want 1", len(result.Resources))
	}

	if result.Resources[0].Name != "bucket2" {
		t.Errorf("MergePolicyChanges() remaining resource = %s, want bucket2", result.Resources[0].Name)
	}
}

// TestMergePolicyChanges_NilChanges tests handling of nil changes
func TestMergePolicyChanges_NilChanges(t *testing.T) {
	base := &types.CollectionResult{
		Principals: []*types.Principal{
			{ARN: "arn:aws:iam::123456789012:user/alice"},
		},
	}

	result, err := MergePolicyChanges(base, nil)
	if err != nil {
		t.Errorf("MergePolicyChanges() error = %v", err)
	}

	if len(result.Principals) != 1 {
		t.Errorf("MergePolicyChanges() Principals count = %d, want 1", len(result.Principals))
	}

	// Verify it's a copy, not the same pointer
	if result == base {
		t.Error("MergePolicyChanges() returned same pointer instead of copy")
	}
}

// TestMergePolicyChanges_NilBase tests error handling for nil base
func TestMergePolicyChanges_NilBase(t *testing.T) {
	changes := &PolicyChanges{
		AddPrincipals: []*types.Principal{
			{ARN: "arn:aws:iam::123456789012:user/alice"},
		},
	}

	_, err := MergePolicyChanges(nil, changes)
	if err == nil {
		t.Error("MergePolicyChanges() expected error for nil base, got nil")
	}
}

// TestCompareAccess_Granted tests detecting newly granted access
func TestCompareAccess_Granted(t *testing.T) {
	// Create before graph (alice has no access)
	beforeResult := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
				Policies:  []types.PolicyDocument{},
			},
		},
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::test-bucket/*",
				Type: types.ResourceTypeS3,
			},
		},
	}

	// Create after graph (alice now has S3 access)
	afterResult := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
				Policies: []types.PolicyDocument{
					{
						Version: "2012-10-17",
						Statements: []types.Statement{
							{
								Effect:   types.EffectAllow,
								Action:   []string{"s3:GetObject"},
								Resource: []string{"arn:aws:s3:::test-bucket/*"},
							},
						},
					},
				},
			},
		},
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::test-bucket/*",
				Type: types.ResourceTypeS3,
			},
		},
	}

	beforeGraph, err := graph.Build(beforeResult)
	if err != nil {
		t.Fatalf("Failed to build before graph: %v", err)
	}

	afterGraph, err := graph.Build(afterResult)
	if err != nil {
		t.Fatalf("Failed to build after graph: %v", err)
	}

	diff, err := CompareAccess(beforeGraph, afterGraph, "arn:aws:s3:::test-bucket/*", "s3:GetObject")
	if err != nil {
		t.Errorf("CompareAccess() error = %v", err)
	}

	if len(diff.Granted) != 1 {
		t.Errorf("CompareAccess() Granted count = %d, want 1", len(diff.Granted))
	}

	if len(diff.Granted) > 0 && diff.Granted[0] != "arn:aws:iam::123456789012:user/alice" {
		t.Errorf("CompareAccess() Granted[0] = %s, want alice", diff.Granted[0])
	}

	if len(diff.Revoked) != 0 {
		t.Errorf("CompareAccess() Revoked count = %d, want 0", len(diff.Revoked))
	}
}

// TestCompareAccess_Revoked tests detecting revoked access
func TestCompareAccess_Revoked(t *testing.T) {
	// Create before graph (alice has S3 access)
	beforeResult := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
				Policies: []types.PolicyDocument{
					{
						Version: "2012-10-17",
						Statements: []types.Statement{
							{
								Effect:   types.EffectAllow,
								Action:   []string{"s3:GetObject"},
								Resource: []string{"arn:aws:s3:::test-bucket/*"},
							},
						},
					},
				},
			},
		},
	}

	// Create after graph (alice's policy removed)
	afterResult := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
				Policies:  []types.PolicyDocument{},
			},
		},
	}

	beforeGraph, err := graph.Build(beforeResult)
	if err != nil {
		t.Fatalf("Failed to build before graph: %v", err)
	}

	afterGraph, err := graph.Build(afterResult)
	if err != nil {
		t.Fatalf("Failed to build after graph: %v", err)
	}

	diff, err := CompareAccess(beforeGraph, afterGraph, "arn:aws:s3:::test-bucket/*", "s3:GetObject")
	if err != nil {
		t.Errorf("CompareAccess() error = %v", err)
	}

	if len(diff.Revoked) != 1 {
		t.Errorf("CompareAccess() Revoked count = %d, want 1", len(diff.Revoked))
	}

	if len(diff.Granted) != 0 {
		t.Errorf("CompareAccess() Granted count = %d, want 0", len(diff.Granted))
	}
}

// TestCompareAccess_Unchanged tests detecting unchanged access
func TestCompareAccess_Unchanged(t *testing.T) {
	// Create identical before and after graphs
	result := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:       "arn:aws:iam::123456789012:user/alice",
				Type:      types.PrincipalTypeUser,
				Name:      "alice",
				AccountID: "123456789012",
				Policies: []types.PolicyDocument{
					{
						Version: "2012-10-17",
						Statements: []types.Statement{
							{
								Effect:   types.EffectAllow,
								Action:   []string{"s3:GetObject"},
								Resource: []string{"arn:aws:s3:::test-bucket/*"},
							},
						},
					},
				},
			},
		},
	}

	beforeGraph, err := graph.Build(result)
	if err != nil {
		t.Fatalf("Failed to build before graph: %v", err)
	}

	afterGraph, err := graph.Build(result)
	if err != nil {
		t.Fatalf("Failed to build after graph: %v", err)
	}

	diff, err := CompareAccess(beforeGraph, afterGraph, "arn:aws:s3:::test-bucket/*", "s3:GetObject")
	if err != nil {
		t.Errorf("CompareAccess() error = %v", err)
	}

	if len(diff.Unchanged) != 1 {
		t.Errorf("CompareAccess() Unchanged count = %d, want 1", len(diff.Unchanged))
	}

	if len(diff.Granted) != 0 {
		t.Errorf("CompareAccess() Granted count = %d, want 0", len(diff.Granted))
	}

	if len(diff.Revoked) != 0 {
		t.Errorf("CompareAccess() Revoked count = %d, want 0", len(diff.Revoked))
	}
}

// TestCompareAccess_NilGraphs tests error handling for nil graphs
func TestCompareAccess_NilGraphs(t *testing.T) {
	result := &types.CollectionResult{
		Principals: []*types.Principal{},
	}

	g, _ := graph.Build(result)

	_, err := CompareAccess(nil, g, "*", "*")
	if err == nil {
		t.Error("CompareAccess() expected error for nil before graph, got nil")
	}

	_, err = CompareAccess(g, nil, "*", "*")
	if err == nil {
		t.Error("CompareAccess() expected error for nil after graph, got nil")
	}
}
