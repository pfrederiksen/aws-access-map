package simulation

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/internal/query"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// LoadFromFile loads a CollectionResult from a JSON file
// This enables policy simulation without connecting to AWS
func LoadFromFile(filePath string) (*types.CollectionResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var result types.CollectionResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", filePath, err)
	}

	return &result, nil
}

// PolicyChanges represents modifications to apply to a CollectionResult
type PolicyChanges struct {
	AddPrincipals    []*types.Principal                        // Principals to add
	RemovePrincipals []string                                  // Principal ARNs to remove
	UpdatePolicies   map[string][]types.PolicyDocument         // PrincipalARN -> new policies to append
	AddResources     []*types.Resource                         // Resources to add
	RemoveResources  []string                                  // Resource ARNs to remove
}

// MergePolicyChanges applies policy modifications to a CollectionResult
// Returns a new CollectionResult with the changes applied
func MergePolicyChanges(base *types.CollectionResult, changes *PolicyChanges) (*types.CollectionResult, error) {
	if base == nil {
		return nil, fmt.Errorf("base CollectionResult cannot be nil")
	}
	if changes == nil {
		// No changes to apply, return a copy of base
		return deepCopyResult(base), nil
	}

	// Deep copy the base result to avoid modifying the original
	modified := deepCopyResult(base)

	// Apply principal additions
	if len(changes.AddPrincipals) > 0 {
		for _, principal := range changes.AddPrincipals {
			modified.Principals = append(modified.Principals, deepCopyPrincipal(principal))
		}
	}

	// Apply policy updates (append new policies to existing principals)
	if len(changes.UpdatePolicies) > 0 {
		for i, principal := range modified.Principals {
			if newPolicies, exists := changes.UpdatePolicies[principal.ARN]; exists {
				// Append new policies to this principal
				modified.Principals[i].Policies = append(modified.Principals[i].Policies, newPolicies...)
			}
		}
	}

	// Apply principal removals
	if len(changes.RemovePrincipals) > 0 {
		removeSet := make(map[string]bool)
		for _, arn := range changes.RemovePrincipals {
			removeSet[arn] = true
		}

		filteredPrincipals := make([]*types.Principal, 0)
		for _, principal := range modified.Principals {
			if !removeSet[principal.ARN] {
				filteredPrincipals = append(filteredPrincipals, principal)
			}
		}
		modified.Principals = filteredPrincipals
	}

	// Apply resource additions
	if len(changes.AddResources) > 0 {
		for _, resource := range changes.AddResources {
			modified.Resources = append(modified.Resources, deepCopyResource(resource))
		}
	}

	// Apply resource removals
	if len(changes.RemoveResources) > 0 {
		removeSet := make(map[string]bool)
		for _, arn := range changes.RemoveResources {
			removeSet[arn] = true
		}

		filteredResources := make([]*types.Resource, 0)
		for _, resource := range modified.Resources {
			if !removeSet[resource.ARN] {
				filteredResources = append(filteredResources, resource)
			}
		}
		modified.Resources = filteredResources
	}

	return modified, nil
}

// AccessDiff represents the difference in access between two policy sets
type AccessDiff struct {
	Granted   []string // Principals who gained access
	Revoked   []string // Principals who lost access
	Unchanged []string // Principals with unchanged access
}

// CompareAccess compares who can access a resource+action between two graphs
func CompareAccess(before, after *graph.Graph, resourceARN, action string) (*AccessDiff, error) {
	if before == nil || after == nil {
		return nil, fmt.Errorf("graphs cannot be nil")
	}

	// Query both graphs for who can access the resource
	beforeQuery := query.New(before)
	afterQuery := query.New(after)

	beforePrincipalsResult, err := beforeQuery.WhoCan(resourceARN, action)
	if err != nil {
		return nil, fmt.Errorf("failed to query before graph: %w", err)
	}

	afterPrincipalsResult, err := afterQuery.WhoCan(resourceARN, action)
	if err != nil {
		return nil, fmt.Errorf("failed to query after graph: %w", err)
	}

	// Extract ARNs from principals
	beforePrincipals := make([]string, 0, len(beforePrincipalsResult))
	for _, p := range beforePrincipalsResult {
		beforePrincipals = append(beforePrincipals, p.ARN)
	}

	afterPrincipals := make([]string, 0, len(afterPrincipalsResult))
	for _, p := range afterPrincipalsResult {
		afterPrincipals = append(afterPrincipals, p.ARN)
	}

	// Convert to sets for easier comparison
	beforeSet := make(map[string]bool)
	for _, arn := range beforePrincipals {
		beforeSet[arn] = true
	}

	afterSet := make(map[string]bool)
	for _, arn := range afterPrincipals {
		afterSet[arn] = true
	}

	diff := &AccessDiff{
		Granted:   []string{},
		Revoked:   []string{},
		Unchanged: []string{},
	}

	// Find granted (in after but not in before)
	for arn := range afterSet {
		if !beforeSet[arn] {
			diff.Granted = append(diff.Granted, arn)
		}
	}

	// Find revoked (in before but not in after)
	for arn := range beforeSet {
		if !afterSet[arn] {
			diff.Revoked = append(diff.Revoked, arn)
		}
	}

	// Find unchanged (in both)
	for arn := range beforeSet {
		if afterSet[arn] {
			diff.Unchanged = append(diff.Unchanged, arn)
		}
	}

	return diff, nil
}

// Helper functions for deep copying

func deepCopyResult(result *types.CollectionResult) *types.CollectionResult {
	if result == nil {
		return nil
	}

	copied := &types.CollectionResult{
		CollectedAt: result.CollectedAt,
		AccountID:   result.AccountID,
		Regions:     make([]string, len(result.Regions)),
	}

	copy(copied.Regions, result.Regions)

	// Deep copy principals
	copied.Principals = make([]*types.Principal, len(result.Principals))
	for i, principal := range result.Principals {
		copied.Principals[i] = deepCopyPrincipal(principal)
	}

	// Deep copy resources
	copied.Resources = make([]*types.Resource, len(result.Resources))
	for i, resource := range result.Resources {
		copied.Resources[i] = deepCopyResource(resource)
	}

	// Copy SCPs
	copied.SCPs = make([]types.PolicyDocument, len(result.SCPs))
	copy(copied.SCPs, result.SCPs)

	// Copy SCP attachments
	copied.SCPAttachments = make([]types.SCPAttachment, len(result.SCPAttachments))
	copy(copied.SCPAttachments, result.SCPAttachments)

	// Copy OU hierarchy
	if result.OUHierarchy != nil {
		copied.OUHierarchy = &types.OUHierarchy{
			AccountID: result.OUHierarchy.AccountID,
			ParentOUs: make([]string, len(result.OUHierarchy.ParentOUs)),
		}
		copy(copied.OUHierarchy.ParentOUs, result.OUHierarchy.ParentOUs)
	}

	return copied
}

func deepCopyPrincipal(principal *types.Principal) *types.Principal {
	if principal == nil {
		return nil
	}

	copied := &types.Principal{
		ARN:       principal.ARN,
		Type:      principal.Type,
		Name:      principal.Name,
		AccountID: principal.AccountID,
	}

	// Copy policies
	copied.Policies = make([]types.PolicyDocument, len(principal.Policies))
	copy(copied.Policies, principal.Policies)

	// Copy trust policy
	if principal.TrustPolicy != nil {
		trustCopy := *principal.TrustPolicy
		copied.TrustPolicy = &trustCopy
	}

	// Copy permissions boundary
	if principal.PermissionsBoundary != nil {
		boundaryCopy := *principal.PermissionsBoundary
		copied.PermissionsBoundary = &boundaryCopy
	}

	// Copy group memberships
	copied.GroupMemberships = make([]string, len(principal.GroupMemberships))
	copy(copied.GroupMemberships, principal.GroupMemberships)

	return copied
}

func deepCopyResource(resource *types.Resource) *types.Resource {
	if resource == nil {
		return nil
	}

	copied := &types.Resource{
		ARN:       resource.ARN,
		Type:      resource.Type,
		Name:      resource.Name,
		Region:    resource.Region,
		AccountID: resource.AccountID,
	}

	// Copy resource policy
	if resource.ResourcePolicy != nil {
		policyCopy := *resource.ResourcePolicy
		copied.ResourcePolicy = &policyCopy
	}

	return copied
}
