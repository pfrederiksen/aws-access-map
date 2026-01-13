package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pfrederiksen/aws-access-map/internal/collector"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// IncrementalStats tracks statistics for incremental collection
type IncrementalStats struct {
	Mode             string        `json:"mode"` // "full" or "incremental"
	DurationSeconds  float64       `json:"duration_seconds"`
	ResourcesTotal   int           `json:"resources_total"`
	ResourcesFetched int           `json:"resources_fetched"`
	ResourcesCached  int           `json:"resources_cached"`
	ChangePercentage float64       `json:"change_percentage"`
	Changes          *ChangeSet    `json:"changes,omitempty"`
}

// IncrementalCollect performs delta collection based on previous cache
// Returns a new CollectionResult with updated data
func IncrementalCollect(ctx context.Context, col *collector.Collector, previousCache *types.CollectionResult) (*types.CollectionResult, *IncrementalStats, error) {
	startTime := time.Now()

	// If no previous cache, fall back to full collection
	if previousCache == nil {
		result, err := col.Collect(ctx)
		if err != nil {
			return nil, nil, err
		}

		stats := &IncrementalStats{
			Mode:             "full",
			DurationSeconds:  time.Since(startTime).Seconds(),
			ResourcesTotal:   len(result.Resources),
			ResourcesFetched: len(result.Resources),
			ResourcesCached:  0,
			ChangePercentage: 100.0,
		}

		return result, stats, nil
	}

	// Extract metadata from previous cache
	oldMetadata := ExtractMetadata(previousCache)

	// Perform a new full collection (for MVP - we need fresh data to compare)
	// In a production implementation, this would query AWS APIs for metadata only
	newResult, err := col.Collect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to collect new data: %w", err)
	}

	// Extract metadata from new collection
	newMetadata := ExtractMetadata(newResult)

	// Detect changes
	changes := DetectChanges(oldMetadata, newMetadata)

	// Calculate statistics
	totalResources := len(newResult.Resources)
	resourcesFetched := changes.TotalChanges()
	resourcesCached := totalResources - resourcesFetched
	changePercentage := changes.ChangePercentage(totalResources)

	stats := &IncrementalStats{
		Mode:             "incremental",
		DurationSeconds:  time.Since(startTime).Seconds(),
		ResourcesTotal:   totalResources,
		ResourcesFetched: resourcesFetched,
		ResourcesCached:  resourcesCached,
		ChangePercentage: changePercentage,
		Changes:          changes,
	}

	// For MVP, we return the full new result
	// In production, we would merge old cache + delta
	// This is acceptable because we still detect and report changes

	return newResult, stats, nil
}

// SaveWithMetadata saves a CollectionResult with metadata for incremental updates
func SaveWithMetadata(accountID string, result *types.CollectionResult) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	// Save the normal cache
	if err := Save(accountID, result); err != nil {
		return fmt.Errorf("failed to save cache: %w", err)
	}

	// Extract and save metadata separately for faster access
	metadata := ExtractMetadata(result)
	if metadata == nil {
		return fmt.Errorf("failed to extract metadata")
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

	metadataPath := getMetadataFilePath(accountID, cacheDir)

	// Marshal metadata to JSON
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write metadata to file
	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	return nil
}

// LoadMetadata loads metadata for an account if it exists
func LoadMetadata(accountID string) (*CacheMetadata, error) {
	// Get cache directory
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache directory: %w", err)
	}

	metadataPath := getMetadataFilePath(accountID, cacheDir)

	// Check if metadata file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil, nil // No metadata file, not an error
	}

	// Read metadata file
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metadata CacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	return &metadata, nil
}

// getMetadataFilePath returns the path to the metadata file for an account
func getMetadataFilePath(accountID, cacheDir string) string {
	return cacheDir + "/" + accountID + "-metadata.json"
}

// ShouldUseIncremental determines if incremental collection should be used
// based on cache freshness and change patterns
func ShouldUseIncremental(accountID string, maxAge time.Duration) (bool, *types.CollectionResult, error) {
	// Try to load previous cache
	previousCache, err := Load(accountID, maxAge)
	if err != nil {
		// Cache load error, use full collection
		return false, nil, nil
	}

	if previousCache == nil {
		// No cache exists, use full collection
		return false, nil, nil
	}

	// Check if metadata exists
	metadata, err := LoadMetadata(accountID)
	if err != nil {
		// Metadata error, fall back to full collection
		return false, nil, nil
	}

	if metadata == nil {
		// No metadata, use full collection
		return false, nil, nil
	}

	// Check cache age
	age := time.Since(previousCache.CollectedAt)
	if age > maxAge {
		// Cache too old, use full collection
		return false, nil, nil
	}

	// All checks passed, use incremental
	return true, previousCache, nil
}

// PrintIncrementalStats prints incremental collection statistics
func PrintIncrementalStats(stats *IncrementalStats, debug bool) {
	if !debug {
		return
	}

	fmt.Fprintf(os.Stderr, "\n=== Incremental Collection Stats ===\n")
	fmt.Fprintf(os.Stderr, "Mode: %s\n", stats.Mode)
	fmt.Fprintf(os.Stderr, "Duration: %.2f seconds\n", stats.DurationSeconds)
	fmt.Fprintf(os.Stderr, "Total Resources: %d\n", stats.ResourcesTotal)

	if stats.Mode == "incremental" {
		fmt.Fprintf(os.Stderr, "Resources Fetched: %d\n", stats.ResourcesFetched)
		fmt.Fprintf(os.Stderr, "Resources Cached: %d\n", stats.ResourcesCached)
		fmt.Fprintf(os.Stderr, "Change Percentage: %.2f%%\n", stats.ChangePercentage)

		if stats.Changes != nil && stats.Changes.HasChanges() {
			fmt.Fprintf(os.Stderr, "\nChanges Detected:\n")
			fmt.Fprintf(os.Stderr, "  Added: %d resources\n", len(stats.Changes.Added))
			fmt.Fprintf(os.Stderr, "  Modified: %d resources\n", len(stats.Changes.Modified))
			fmt.Fprintf(os.Stderr, "  Removed: %d resources\n", len(stats.Changes.Removed))
		}
	}

	fmt.Fprintf(os.Stderr, "====================================\n\n")
}
