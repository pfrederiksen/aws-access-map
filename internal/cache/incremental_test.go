package cache

import (
	"testing"
	"time"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestSaveWithMetadata tests saving a result with metadata
func TestSaveWithMetadata(t *testing.T) {
	// Create a temporary cache directory for testing
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

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

	// Save with metadata
	err := SaveWithMetadata("123456789012", result)
	if err != nil {
		t.Errorf("SaveWithMetadata() error = %v", err)
	}

	// Verify normal cache was saved
	cached, err := Load("123456789012", 24*time.Hour)
	if err != nil {
		t.Errorf("Load() error = %v", err)
	}
	if cached == nil {
		t.Error("Load() returned nil after SaveWithMetadata")
	}

	// Verify metadata was saved
	metadata, err := LoadMetadata("123456789012")
	if err != nil {
		t.Errorf("LoadMetadata() error = %v", err)
	}
	if metadata == nil {
		t.Error("LoadMetadata() returned nil after SaveWithMetadata")
	}

	if metadata != nil {
		if metadata.AccountID != "123456789012" {
			t.Errorf("LoadMetadata() AccountID = %s, want 123456789012", metadata.AccountID)
		}
		if len(metadata.Resources) != 1 {
			t.Errorf("LoadMetadata() Resources count = %d, want 1", len(metadata.Resources))
		}
	}
}

// TestLoadMetadata_NoFile tests loading when no metadata file exists
func TestLoadMetadata_NoFile(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	metadata, err := LoadMetadata("nonexistent")
	if err != nil {
		t.Errorf("LoadMetadata() unexpected error: %v", err)
	}
	if metadata != nil {
		t.Error("LoadMetadata() should return nil when no file exists")
	}
}

// TestShouldUseIncremental_NoCache tests when no cache exists
func TestShouldUseIncremental_NoCache(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	shouldUse, cache, err := ShouldUseIncremental("nonexistent", 24*time.Hour)
	if err != nil {
		t.Errorf("ShouldUseIncremental() error = %v", err)
	}
	if shouldUse {
		t.Error("ShouldUseIncremental() = true, want false when no cache exists")
	}
	if cache != nil {
		t.Error("ShouldUseIncremental() returned cache when none exists")
	}
}

// TestShouldUseIncremental_WithValidCache tests when valid cache exists
func TestShouldUseIncremental_WithValidCache(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	result := &types.CollectionResult{
		AccountID:   "123456789012",
		CollectedAt: time.Now(),
		Resources: []*types.Resource{
			{ARN: "arn:aws:s3:::bucket1", Type: types.ResourceTypeS3},
		},
	}

	// Save with metadata
	err := SaveWithMetadata("123456789012", result)
	if err != nil {
		t.Fatalf("SaveWithMetadata() error = %v", err)
	}

	// Check if incremental should be used
	shouldUse, cache, err := ShouldUseIncremental("123456789012", 24*time.Hour)
	if err != nil {
		t.Errorf("ShouldUseIncremental() error = %v", err)
	}
	if !shouldUse {
		t.Error("ShouldUseIncremental() = false, want true when valid cache exists")
	}
	if cache == nil {
		t.Error("ShouldUseIncremental() returned nil cache when valid cache exists")
	}
}

// TestShouldUseIncremental_StaleCache tests when cache is too old
func TestShouldUseIncremental_StaleCache(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	result := &types.CollectionResult{
		AccountID:   "123456789012",
		CollectedAt: time.Now().Add(-48 * time.Hour), // 2 days old
		Resources: []*types.Resource{
			{ARN: "arn:aws:s3:::bucket1", Type: types.ResourceTypeS3},
		},
	}

	// Save with metadata
	err := SaveWithMetadata("123456789012", result)
	if err != nil {
		t.Fatalf("SaveWithMetadata() error = %v", err)
	}

	// Check with 24h TTL (cache is 48h old)
	shouldUse, _, err := ShouldUseIncremental("123456789012", 24*time.Hour)
	if err != nil {
		t.Errorf("ShouldUseIncremental() error = %v", err)
	}
	if shouldUse {
		t.Error("ShouldUseIncremental() = true, want false when cache is stale")
	}
}

// TestIncrementalStats_ChangePercentage tests statistics calculation
func TestIncrementalStats_ChangePercentage(t *testing.T) {
	stats := &IncrementalStats{
		Mode:             "incremental",
		ResourcesTotal:   100,
		ResourcesFetched: 10,
		ResourcesCached:  90,
		ChangePercentage: 10.0,
		Changes: &ChangeSet{
			Added:    []string{"arn1", "arn2"},
			Modified: []string{"arn3", "arn4", "arn5"},
			Removed:  []string{"arn6"},
		},
	}

	// Verify change percentage calculation
	expectedPercentage := 6.0 // 6 changes out of 100 resources
	actualPercentage := stats.Changes.ChangePercentage(stats.ResourcesTotal)

	if actualPercentage != expectedPercentage {
		t.Errorf("ChangePercentage() = %f, want %f", actualPercentage, expectedPercentage)
	}
}

// TestIncrementalStats_NoChanges tests when there are no changes
func TestIncrementalStats_NoChanges(t *testing.T) {
	changes := &ChangeSet{
		Added:    []string{},
		Modified: []string{},
		Removed:  []string{},
	}

	if changes.HasChanges() {
		t.Error("HasChanges() = true, want false when no changes")
	}

	if changes.TotalChanges() != 0 {
		t.Errorf("TotalChanges() = %d, want 0", changes.TotalChanges())
	}
}

// Note: Test helper functions setupTestCacheDir and cleanupTestCacheDir
// are defined in cache_test.go and shared across test files

// TestPrintIncrementalStats tests statistics printing (just ensure it doesn't panic)
func TestPrintIncrementalStats(t *testing.T) {
	stats := &IncrementalStats{
		Mode:             "incremental",
		DurationSeconds:  5.2,
		ResourcesTotal:   100,
		ResourcesFetched: 10,
		ResourcesCached:  90,
		ChangePercentage: 10.0,
		Changes: &ChangeSet{
			Added:    []string{"arn1"},
			Modified: []string{"arn2"},
			Removed:  []string{},
		},
	}

	// Should not panic when debug is true
	PrintIncrementalStats(stats, true)

	// Should not panic when debug is false
	PrintIncrementalStats(stats, false)
}

// TestSaveWithMetadata_NilResult tests error handling for nil result
func TestSaveWithMetadata_NilResult(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	err := SaveWithMetadata("123", nil)
	if err == nil {
		t.Error("SaveWithMetadata(nil) should return error")
	}
}
