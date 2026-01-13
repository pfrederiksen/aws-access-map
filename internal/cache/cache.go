package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

const (
	// DefaultTTL is the default cache expiration time (24 hours)
	DefaultTTL = 24 * time.Hour

	// CacheDirName is the directory name under user's home for cache storage
	CacheDirName = ".aws-access-map/cache"
)

// Save writes a CollectionResult to the cache
// The cache file is named: <accountID>-<timestamp>.json
func Save(accountID string, result *types.CollectionResult) error {
	if accountID == "" {
		return fmt.Errorf("accountID cannot be empty")
	}

	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return fmt.Errorf("failed to get cache directory: %w", err)
	}

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Remove old cache files for this account
	if err := clearAccountCache(cacheDir, accountID); err != nil {
		// Log but don't fail - we can still save new cache
		fmt.Fprintf(os.Stderr, "Warning: failed to clear old cache: %v\n", err)
	}

	// Generate cache file path with current timestamp
	timestamp := time.Now().Format("20060102-150405") // YYYYMMDD-HHMMSS
	filename := fmt.Sprintf("%s-%s.json", accountID, timestamp)
	filePath := filepath.Join(cacheDir, filename)

	// Marshal result to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}

	return nil
}

// Load reads a CollectionResult from the cache
// Returns nil if cache doesn't exist or is stale (older than TTL)
// Returns error only for unexpected failures (not for missing/stale cache)
func Load(accountID string, ttl time.Duration) (*types.CollectionResult, error) {
	if accountID == "" {
		return nil, fmt.Errorf("accountID cannot be empty")
	}

	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache directory: %w", err)
	}

	// Check if cache directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		// Cache directory doesn't exist - no cache available
		return nil, nil
	}

	// Find most recent cache file for this account
	cacheFile, err := findLatestCacheFile(cacheDir, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to find cache file: %w", err)
	}

	if cacheFile == "" {
		// No cache file found
		return nil, nil
	}

	// Check file modification time
	info, err := os.Stat(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to stat cache file: %w", err)
	}

	// Check if cache is stale
	age := time.Since(info.ModTime())
	if age > ttl {
		// Cache is stale
		return nil, nil
	}

	// Read and unmarshal cache file
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var result types.CollectionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	return &result, nil
}

// Clear deletes cache files
// If accountID is empty, clears all cache files
// If accountID is specified, only clears cache for that account
func Clear(accountID string) error {
	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return fmt.Errorf("failed to get cache directory: %w", err)
	}

	// Check if cache directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		// Nothing to clear
		return nil
	}

	if accountID == "" {
		// Clear entire cache directory
		if err := os.RemoveAll(cacheDir); err != nil {
			return fmt.Errorf("failed to remove cache directory: %w", err)
		}
		return nil
	}

	// Clear cache for specific account
	return clearAccountCache(cacheDir, accountID)
}

// getCacheDir returns the cache directory path
// Expands ~ to user's home directory
func getCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	return filepath.Join(home, CacheDirName), nil
}

// findLatestCacheFile finds the most recent cache file for an account
// Returns empty string if no cache file found
func findLatestCacheFile(cacheDir, accountID string) (string, error) {
	// Read directory entries
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", fmt.Errorf("failed to read cache directory: %w", err)
	}

	// Find all cache files for this account
	prefix := accountID + "-"
	var latestFile string
	var latestTime time.Time

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}

		// Get file info to check modification time
		filePath := filepath.Join(cacheDir, name)
		info, err := os.Stat(filePath)
		if err != nil {
			continue
		}

		// Track latest file
		if latestFile == "" || info.ModTime().After(latestTime) {
			latestFile = filePath
			latestTime = info.ModTime()
		}
	}

	return latestFile, nil
}

// clearAccountCache removes all cache files for a specific account
func clearAccountCache(cacheDir, accountID string) error {
	// Read directory entries
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	// Delete all cache files for this account
	prefix := accountID + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".json") {
			continue
		}

		filePath := filepath.Join(cacheDir, name)
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("failed to remove cache file %s: %w", name, err)
		}
	}

	return nil
}

// GetCacheInfo returns information about cached data for an account
// Returns empty string and zero time if no cache exists
func GetCacheInfo(accountID string) (filePath string, modTime time.Time, err error) {
	if accountID == "" {
		return "", time.Time{}, fmt.Errorf("accountID cannot be empty")
	}

	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get cache directory: %w", err)
	}

	// Check if cache directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		return "", time.Time{}, nil
	}

	// Find most recent cache file
	cacheFile, err := findLatestCacheFile(cacheDir, accountID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to find cache file: %w", err)
	}

	if cacheFile == "" {
		return "", time.Time{}, nil
	}

	// Get file info
	info, err := os.Stat(cacheFile)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to stat cache file: %w", err)
	}

	return cacheFile, info.ModTime(), nil
}
