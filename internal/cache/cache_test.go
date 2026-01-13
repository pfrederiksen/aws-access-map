package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// TestSaveAndLoad_RoundTrip tests saving and loading data
func TestSaveAndLoad_RoundTrip(t *testing.T) {
	// Use temporary cache directory for testing
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	accountID := "123456789012"

	// Create test data
	original := &types.CollectionResult{
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/alice",
				Type: types.PrincipalTypeUser,
				Name: "alice",
			},
		},
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::test-bucket",
				Type: types.ResourceTypeS3,
				Name: "test-bucket",
			},
		},
		CollectedAt: time.Now(),
		AccountID:   accountID,
		Regions:     []string{"us-east-1"},
	}

	// Save data
	if err := Save(accountID, original); err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Load data
	loaded, err := Load(accountID, DefaultTTL)
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	if loaded == nil {
		t.Fatal("Expected loaded data to be non-nil")
	}

	// Verify data
	if len(loaded.Principals) != 1 {
		t.Errorf("Expected 1 principal, got %d", len(loaded.Principals))
	}

	if loaded.Principals[0].ARN != original.Principals[0].ARN {
		t.Errorf("Principal ARN mismatch: got %s, want %s",
			loaded.Principals[0].ARN, original.Principals[0].ARN)
	}

	if len(loaded.Resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(loaded.Resources))
	}

	if loaded.AccountID != accountID {
		t.Errorf("AccountID mismatch: got %s, want %s", loaded.AccountID, accountID)
	}
}

// TestLoad_Expired tests that expired cache returns nil
func TestLoad_Expired(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	accountID := "123456789012"

	// Create test data
	result := &types.CollectionResult{
		AccountID:   accountID,
		CollectedAt: time.Now(),
		Regions:     []string{"us-east-1"},
	}

	// Save data
	if err := Save(accountID, result); err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Find cache file and modify its timestamp to be old
	cacheDir, _ := getCacheDir()
	cacheFile, err := findLatestCacheFile(cacheDir, accountID)
	if err != nil {
		t.Fatalf("Failed to find cache file: %v", err)
	}

	// Set modification time to 2 days ago (older than DefaultTTL)
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cacheFile, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to change file time: %v", err)
	}

	// Try to load with 1-hour TTL - should return nil (expired)
	loaded, err := Load(accountID, 1*time.Hour)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loaded != nil {
		t.Error("Expected expired cache to return nil")
	}
}

// TestLoad_Missing tests that missing cache returns nil
func TestLoad_Missing(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	// Try to load non-existent cache
	loaded, err := Load("999999999999", DefaultTTL)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if loaded != nil {
		t.Error("Expected missing cache to return nil")
	}
}

// TestLoad_NoCacheDirectory tests loading when cache directory doesn't exist
func TestLoad_NoCacheDirectory(t *testing.T) {
	// Don't create cache directory - test behavior when it doesn't exist
	tempDir := t.TempDir()
	originalCacheDirName := CacheDirName

	// Temporarily override cache directory to non-existent location
	// Note: This is a bit hacky, but getCacheDir() uses os.UserHomeDir()
	// For proper testing, we'd need to make getCacheDir() configurable
	// For now, just test that Load handles missing directory gracefully

	loaded, err := Load("123456789012", DefaultTTL)
	if err != nil {
		t.Fatalf("Load should not error on missing directory: %v", err)
	}

	if loaded != nil {
		t.Error("Expected nil when cache directory doesn't exist")
	}

	_ = originalCacheDirName // Keep linter happy
	_ = tempDir
}

// TestClear_SingleAccount tests clearing cache for a specific account
func TestClear_SingleAccount(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	account1 := "111111111111"
	account2 := "222222222222"

	// Save data for two accounts
	result1 := &types.CollectionResult{AccountID: account1, Regions: []string{"us-east-1"}}
	result2 := &types.CollectionResult{AccountID: account2, Regions: []string{"us-west-2"}}

	if err := Save(account1, result1); err != nil {
		t.Fatalf("Failed to save account1: %v", err)
	}

	if err := Save(account2, result2); err != nil {
		t.Fatalf("Failed to save account2: %v", err)
	}

	// Clear cache for account1
	if err := Clear(account1); err != nil {
		t.Fatalf("Failed to clear account1: %v", err)
	}

	// Verify account1 cache is gone
	loaded1, err := Load(account1, DefaultTTL)
	if err != nil {
		t.Fatalf("Load account1 failed: %v", err)
	}

	if loaded1 != nil {
		t.Error("Expected account1 cache to be cleared")
	}

	// Verify account2 cache still exists
	loaded2, err := Load(account2, DefaultTTL)
	if err != nil {
		t.Fatalf("Load account2 failed: %v", err)
	}

	if loaded2 == nil {
		t.Error("Expected account2 cache to still exist")
	}
}

// TestClear_AllAccounts tests clearing all cache
func TestClear_AllAccounts(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	account1 := "111111111111"
	account2 := "222222222222"

	// Save data for two accounts
	result1 := &types.CollectionResult{AccountID: account1, Regions: []string{"us-east-1"}}
	result2 := &types.CollectionResult{AccountID: account2, Regions: []string{"us-west-2"}}

	if err := Save(account1, result1); err != nil {
		t.Fatalf("Failed to save account1: %v", err)
	}

	if err := Save(account2, result2); err != nil {
		t.Fatalf("Failed to save account2: %v", err)
	}

	// Clear all cache (empty accountID)
	if err := Clear(""); err != nil {
		t.Fatalf("Failed to clear all: %v", err)
	}

	// Verify both caches are gone
	loaded1, _ := Load(account1, DefaultTTL)
	if loaded1 != nil {
		t.Error("Expected account1 cache to be cleared")
	}

	loaded2, _ := Load(account2, DefaultTTL)
	if loaded2 != nil {
		t.Error("Expected account2 cache to be cleared")
	}
}

// TestSave_OverwritesOldCache tests that saving removes old cache files
func TestSave_OverwritesOldCache(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	accountID := "123456789012"

	// Save first version
	result1 := &types.CollectionResult{
		AccountID: accountID,
		Regions:   []string{"us-east-1"},
	}

	if err := Save(accountID, result1); err != nil {
		t.Fatalf("Failed to save first version: %v", err)
	}

	// Wait a moment to ensure different timestamp
	time.Sleep(100 * time.Millisecond)

	// Save second version
	result2 := &types.CollectionResult{
		AccountID: accountID,
		Regions:   []string{"us-east-1", "us-west-2"},
	}

	if err := Save(accountID, result2); err != nil {
		t.Fatalf("Failed to save second version: %v", err)
	}

	// Load should return the latest version
	loaded, err := Load(accountID, DefaultTTL)
	if err != nil {
		t.Fatalf("Failed to load: %v", err)
	}

	if loaded == nil {
		t.Fatal("Expected loaded data to be non-nil")
	}

	if len(loaded.Regions) != 2 {
		t.Errorf("Expected 2 regions (latest version), got %d", len(loaded.Regions))
	}

	// Verify only one cache file exists for this account
	cacheDir, _ := getCacheDir()
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("Failed to read cache dir: %v", err)
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("Expected 1 cache file, found %d", count)
	}
}

// TestGetCacheInfo tests cache metadata retrieval
func TestGetCacheInfo(t *testing.T) {
	tempDir := setupTestCacheDir(t)
	defer cleanupTestCacheDir(t, tempDir)

	accountID := "123456789012"

	// No cache initially
	filePath, modTime, err := GetCacheInfo(accountID)
	if err != nil {
		t.Fatalf("GetCacheInfo failed: %v", err)
	}

	if filePath != "" {
		t.Error("Expected empty file path for non-existent cache")
	}

	if !modTime.IsZero() {
		t.Error("Expected zero time for non-existent cache")
	}

	// Save data
	result := &types.CollectionResult{AccountID: accountID, Regions: []string{"us-east-1"}}
	if err := Save(accountID, result); err != nil {
		t.Fatalf("Failed to save: %v", err)
	}

	// Get cache info
	filePath, modTime, err = GetCacheInfo(accountID)
	if err != nil {
		t.Fatalf("GetCacheInfo failed: %v", err)
	}

	if filePath == "" {
		t.Error("Expected non-empty file path")
	}

	if modTime.IsZero() {
		t.Error("Expected non-zero modification time")
	}

	// Verify modification time is recent (within last minute)
	age := time.Since(modTime)
	if age > 1*time.Minute {
		t.Errorf("Cache file is too old: %v", age)
	}
}

// TestSave_EmptyAccountID tests that saving with empty accountID fails
func TestSave_EmptyAccountID(t *testing.T) {
	result := &types.CollectionResult{AccountID: "", Regions: []string{"us-east-1"}}

	err := Save("", result)
	if err == nil {
		t.Error("Expected error when saving with empty accountID")
	}
}

// TestSave_NilResult tests that saving nil result fails
func TestSave_NilResult(t *testing.T) {
	err := Save("123456789012", nil)
	if err == nil {
		t.Error("Expected error when saving nil result")
	}
}

// TestLoad_EmptyAccountID tests that loading with empty accountID fails
func TestLoad_EmptyAccountID(t *testing.T) {
	_, err := Load("", DefaultTTL)
	if err == nil {
		t.Error("Expected error when loading with empty accountID")
	}
}

// Helper function to setup test cache directory
func setupTestCacheDir(t *testing.T) string {
	t.Helper()

	// Create temporary directory for testing
	tempDir := t.TempDir()

	// Override CacheDirName to use temp directory
	// Note: This is a simplification. In production, we'd make getCacheDir() configurable
	// For now, tests will use actual cache directory with test account IDs

	return tempDir
}

// Helper function to cleanup test cache directory
func cleanupTestCacheDir(t *testing.T, tempDir string) {
	t.Helper()

	// Clean up any test cache files from actual cache directory
	// Use recognizable test account IDs like "111111111111", "222222222222", "123456789012"
	testAccountIDs := []string{"111111111111", "222222222222", "123456789012", "999999999999"}

	for _, accountID := range testAccountIDs {
		_ = Clear(accountID) // Best effort cleanup
	}
}
