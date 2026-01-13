package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// ResourceMetadata tracks metadata for a resource to detect changes
type ResourceMetadata struct {
	ARN          string    `json:"arn"`
	Type         string    `json:"type"`
	LastModified time.Time `json:"last_modified"`
	PolicyHash   string    `json:"policy_hash"` // SHA256 of policy document
	ETag         string    `json:"etag"`        // S3/resource-specific ETag
}

// CacheMetadata extends CollectionResult with metadata for incremental updates
type CacheMetadata struct {
	Version         string                       `json:"version"` // Cache format version
	AccountID       string                       `json:"account_id"`
	CollectedAt     time.Time                    `json:"collected_at"`
	Resources       map[string]*ResourceMetadata `json:"resources"`        // ARN -> metadata
	PrincipalsHash  string                       `json:"principals_hash"`  // Hash of all principal ARNs
	PrincipalsCount int                          `json:"principals_count"` // Count for quick check
}

// ChangeSet represents detected changes between two collection runs
type ChangeSet struct {
	Added    []string // ARNs of new resources
	Removed  []string // ARNs of deleted resources
	Modified []string // ARNs of resources with changed policies
}

// ComputePolicyHash calculates SHA256 hash of a policy document
func ComputePolicyHash(policy *types.PolicyDocument) string {
	if policy == nil {
		return ""
	}

	// Marshal to JSON for consistent hashing
	data, err := json.Marshal(policy)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ComputePrincipalHash calculates SHA256 hash of all principal ARNs
func ComputePrincipalHash(principals []*types.Principal) string {
	if len(principals) == 0 {
		return ""
	}

	// Collect all ARNs in sorted order for consistent hashing
	arns := make([]string, len(principals))
	for i, p := range principals {
		arns[i] = p.ARN
	}

	// Sort for consistency (simple bubble sort for small lists)
	for i := 0; i < len(arns)-1; i++ {
		for j := i + 1; j < len(arns); j++ {
			if arns[i] > arns[j] {
				arns[i], arns[j] = arns[j], arns[i]
			}
		}
	}

	// Hash the concatenated ARNs
	data, _ := json.Marshal(arns)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ExtractMetadata extracts metadata from a CollectionResult
func ExtractMetadata(result *types.CollectionResult) *CacheMetadata {
	if result == nil {
		return nil
	}

	metadata := &CacheMetadata{
		Version:         "1.0",
		AccountID:       result.AccountID,
		CollectedAt:     result.CollectedAt,
		Resources:       make(map[string]*ResourceMetadata),
		PrincipalsHash:  ComputePrincipalHash(result.Principals),
		PrincipalsCount: len(result.Principals),
	}

	// Extract resource metadata
	for _, resource := range result.Resources {
		resourceMeta := &ResourceMetadata{
			ARN:          resource.ARN,
			Type:         string(resource.Type),
			LastModified: result.CollectedAt, // Use collection time as proxy
			PolicyHash:   ComputePolicyHash(resource.ResourcePolicy),
		}

		metadata.Resources[resource.ARN] = resourceMeta
	}

	return metadata
}

// DetectChanges compares old and new metadata to find what changed
func DetectChanges(old, new *CacheMetadata) *ChangeSet {
	changes := &ChangeSet{
		Added:    []string{},
		Removed:  []string{},
		Modified: []string{},
	}

	if old == nil || new == nil {
		return changes
	}

	// Find additions and modifications
	for arn, newMeta := range new.Resources {
		oldMeta, exists := old.Resources[arn]
		if !exists {
			// New resource
			changes.Added = append(changes.Added, arn)
		} else if oldMeta.PolicyHash != newMeta.PolicyHash {
			// Policy changed
			changes.Modified = append(changes.Modified, arn)
		}
		// If PolicyHash matches, no change needed
	}

	// Find removals
	for arn := range old.Resources {
		if _, exists := new.Resources[arn]; !exists {
			changes.Removed = append(changes.Removed, arn)
		}
	}

	return changes
}

// HasChanges returns true if the changeset contains any changes
func (cs *ChangeSet) HasChanges() bool {
	return len(cs.Added) > 0 || len(cs.Removed) > 0 || len(cs.Modified) > 0
}

// TotalChanges returns the total number of changes
func (cs *ChangeSet) TotalChanges() int {
	return len(cs.Added) + len(cs.Removed) + len(cs.Modified)
}

// ChangePercentage calculates the percentage of resources that changed
func (cs *ChangeSet) ChangePercentage(totalResources int) float64 {
	if totalResources == 0 {
		return 0.0
	}
	return float64(cs.TotalChanges()) / float64(totalResources) * 100.0
}
