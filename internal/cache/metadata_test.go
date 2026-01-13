package cache

import (
	"testing"
	"time"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestComputePolicyHash tests policy hashing consistency
func TestComputePolicyHash(t *testing.T) {
	policy1 := &types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   []string{"s3:GetObject"},
				Resource: []string{"arn:aws:s3:::bucket/*"},
			},
		},
	}

	policy2 := &types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   []string{"s3:GetObject"},
				Resource: []string{"arn:aws:s3:::bucket/*"},
			},
		},
	}

	policy3 := &types.PolicyDocument{
		Version: "2012-10-17",
		Statements: []types.Statement{
			{
				Effect:   types.EffectAllow,
				Action:   []string{"s3:PutObject"}, // Different action
				Resource: []string{"arn:aws:s3:::bucket/*"},
			},
		},
	}

	hash1 := ComputePolicyHash(policy1)
	hash2 := ComputePolicyHash(policy2)
	hash3 := ComputePolicyHash(policy3)

	// Same policies should have same hash
	if hash1 != hash2 {
		t.Errorf("ComputePolicyHash() not consistent: hash1=%s, hash2=%s", hash1, hash2)
	}

	// Different policies should have different hash
	if hash1 == hash3 {
		t.Errorf("ComputePolicyHash() same hash for different policies: %s", hash1)
	}

	// Hash should not be empty
	if hash1 == "" {
		t.Error("ComputePolicyHash() returned empty hash")
	}
}

// TestComputePolicyHash_NilPolicy tests handling of nil policy
func TestComputePolicyHash_NilPolicy(t *testing.T) {
	hash := ComputePolicyHash(nil)
	if hash != "" {
		t.Errorf("ComputePolicyHash(nil) = %s, want empty string", hash)
	}
}

// TestComputePrincipalHash tests principal hash consistency
func TestComputePrincipalHash(t *testing.T) {
	principals1 := []*types.Principal{
		{ARN: "arn:aws:iam::123:user/alice"},
		{ARN: "arn:aws:iam::123:user/bob"},
	}

	principals2 := []*types.Principal{
		{ARN: "arn:aws:iam::123:user/bob"},
		{ARN: "arn:aws:iam::123:user/alice"},
	}

	principals3 := []*types.Principal{
		{ARN: "arn:aws:iam::123:user/alice"},
		{ARN: "arn:aws:iam::123:user/charlie"},
	}

	hash1 := ComputePrincipalHash(principals1)
	hash2 := ComputePrincipalHash(principals2)
	hash3 := ComputePrincipalHash(principals3)

	// Same principals in different order should have same hash (sorted)
	if hash1 != hash2 {
		t.Errorf("ComputePrincipalHash() not order-independent: hash1=%s, hash2=%s", hash1, hash2)
	}

	// Different principals should have different hash
	if hash1 == hash3 {
		t.Errorf("ComputePrincipalHash() same hash for different principals: %s", hash1)
	}
}

// TestExtractMetadata tests metadata extraction
func TestExtractMetadata(t *testing.T) {
	result := &types.CollectionResult{
		AccountID:   "123456789012",
		CollectedAt: time.Now(),
		Principals: []*types.Principal{
			{ARN: "arn:aws:iam::123:user/alice"},
		},
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::bucket1",
				Type: types.ResourceTypeS3,
				ResourcePolicy: &types.PolicyDocument{
					Version: "2012-10-17",
					Statements: []types.Statement{
						{Effect: types.EffectAllow, Action: []string{"s3:GetObject"}},
					},
				},
			},
		},
	}

	metadata := ExtractMetadata(result)

	if metadata == nil {
		t.Fatal("ExtractMetadata() returned nil")
	}

	if metadata.AccountID != result.AccountID {
		t.Errorf("ExtractMetadata() AccountID = %s, want %s", metadata.AccountID, result.AccountID)
	}

	if metadata.PrincipalsCount != 1 {
		t.Errorf("ExtractMetadata() PrincipalsCount = %d, want 1", metadata.PrincipalsCount)
	}

	if len(metadata.Resources) != 1 {
		t.Errorf("ExtractMetadata() Resources count = %d, want 1", len(metadata.Resources))
	}

	resourceMeta, exists := metadata.Resources["arn:aws:s3:::bucket1"]
	if !exists {
		t.Error("ExtractMetadata() missing resource metadata for bucket1")
	}

	if resourceMeta.PolicyHash == "" {
		t.Error("ExtractMetadata() PolicyHash is empty")
	}
}

// TestExtractMetadata_NilResult tests handling of nil result
func TestExtractMetadata_NilResult(t *testing.T) {
	metadata := ExtractMetadata(nil)
	if metadata != nil {
		t.Error("ExtractMetadata(nil) should return nil")
	}
}

// TestDetectChanges_Added tests detecting new resources
func TestDetectChanges_Added(t *testing.T) {
	old := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {
				ARN:        "arn:aws:s3:::bucket1",
				PolicyHash: "hash1",
			},
		},
	}

	new := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {
				ARN:        "arn:aws:s3:::bucket1",
				PolicyHash: "hash1",
			},
			"arn:aws:s3:::bucket2": {
				ARN:        "arn:aws:s3:::bucket2",
				PolicyHash: "hash2",
			},
		},
	}

	changes := DetectChanges(old, new)

	if len(changes.Added) != 1 {
		t.Errorf("DetectChanges() Added count = %d, want 1", len(changes.Added))
	}

	if len(changes.Added) > 0 && changes.Added[0] != "arn:aws:s3:::bucket2" {
		t.Errorf("DetectChanges() Added[0] = %s, want bucket2", changes.Added[0])
	}

	if len(changes.Removed) != 0 {
		t.Errorf("DetectChanges() Removed count = %d, want 0", len(changes.Removed))
	}

	if len(changes.Modified) != 0 {
		t.Errorf("DetectChanges() Modified count = %d, want 0", len(changes.Modified))
	}
}

// TestDetectChanges_Removed tests detecting deleted resources
func TestDetectChanges_Removed(t *testing.T) {
	old := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {ARN: "arn:aws:s3:::bucket1"},
			"arn:aws:s3:::bucket2": {ARN: "arn:aws:s3:::bucket2"},
		},
	}

	new := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {ARN: "arn:aws:s3:::bucket1"},
		},
	}

	changes := DetectChanges(old, new)

	if len(changes.Removed) != 1 {
		t.Errorf("DetectChanges() Removed count = %d, want 1", len(changes.Removed))
	}

	if len(changes.Removed) > 0 && changes.Removed[0] != "arn:aws:s3:::bucket2" {
		t.Errorf("DetectChanges() Removed[0] = %s, want bucket2", changes.Removed[0])
	}
}

// TestDetectChanges_Modified tests detecting policy changes
func TestDetectChanges_Modified(t *testing.T) {
	old := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {
				ARN:        "arn:aws:s3:::bucket1",
				PolicyHash: "oldhash",
			},
		},
	}

	new := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {
				ARN:        "arn:aws:s3:::bucket1",
				PolicyHash: "newhash",
			},
		},
	}

	changes := DetectChanges(old, new)

	if len(changes.Modified) != 1 {
		t.Errorf("DetectChanges() Modified count = %d, want 1", len(changes.Modified))
	}

	if len(changes.Modified) > 0 && changes.Modified[0] != "arn:aws:s3:::bucket1" {
		t.Errorf("DetectChanges() Modified[0] = %s, want bucket1", changes.Modified[0])
	}
}

// TestDetectChanges_NoChanges tests when nothing changed
func TestDetectChanges_NoChanges(t *testing.T) {
	metadata := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{
			"arn:aws:s3:::bucket1": {
				ARN:        "arn:aws:s3:::bucket1",
				PolicyHash: "hash1",
			},
		},
	}

	changes := DetectChanges(metadata, metadata)

	if changes.HasChanges() {
		t.Error("DetectChanges() reported changes when none exist")
	}

	if changes.TotalChanges() != 0 {
		t.Errorf("DetectChanges() TotalChanges = %d, want 0", changes.TotalChanges())
	}
}

// TestDetectChanges_NilMetadata tests handling of nil metadata
func TestDetectChanges_NilMetadata(t *testing.T) {
	metadata := &CacheMetadata{
		Resources: map[string]*ResourceMetadata{},
	}

	changes1 := DetectChanges(nil, metadata)
	if changes1 == nil {
		t.Error("DetectChanges(nil, metadata) returned nil")
	}

	changes2 := DetectChanges(metadata, nil)
	if changes2 == nil {
		t.Error("DetectChanges(metadata, nil) returned nil")
	}
}

// TestChangeSet_ChangePercentage tests percentage calculation
func TestChangeSet_ChangePercentage(t *testing.T) {
	changes := &ChangeSet{
		Added:    []string{"arn1", "arn2"},
		Modified: []string{"arn3"},
		Removed:  []string{},
	}

	// 3 changes out of 100 resources = 3%
	percentage := changes.ChangePercentage(100)
	if percentage != 3.0 {
		t.Errorf("ChangePercentage(100) = %f, want 3.0", percentage)
	}

	// Handle zero resources
	percentage = changes.ChangePercentage(0)
	if percentage != 0.0 {
		t.Errorf("ChangePercentage(0) = %f, want 0.0", percentage)
	}
}

// TestChangeSet_HasChanges tests change detection
func TestChangeSet_HasChanges(t *testing.T) {
	emptyChanges := &ChangeSet{}
	if emptyChanges.HasChanges() {
		t.Error("Empty ChangeSet should not have changes")
	}

	withChanges := &ChangeSet{
		Added: []string{"arn1"},
	}
	if !withChanges.HasChanges() {
		t.Error("ChangeSet with additions should have changes")
	}
}
