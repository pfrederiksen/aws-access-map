package policy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/gobwas/glob"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// Parse parses a URL-encoded policy document string
func Parse(policyDoc string) (*types.PolicyDocument, error) {
	// URL decode if needed
	decoded, err := url.QueryUnescape(policyDoc)
	if err != nil {
		// If decode fails, assume it's already decoded
		decoded = policyDoc
	}

	var policy types.PolicyDocument
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy document: %w", err)
	}

	return &policy, nil
}

// MatchesAction checks if an action pattern matches a specific action
// Supports AWS IAM action wildcards: *, s3:*, s3:Get*, iam:*User*, etc.
func MatchesAction(pattern, action string) bool {
	// Exact match (most common case)
	if pattern == action {
		return true
	}

	// Universal wildcard
	if pattern == "*" {
		return true
	}

	// AWS uses case-sensitive action matching, but normalize for consistency
	pattern = strings.ToLower(pattern)
	action = strings.ToLower(action)

	// Compile glob pattern (gobwas/glob handles *, ?, [...], etc.)
	g, err := glob.Compile(pattern)
	if err != nil {
		// If pattern is invalid, fall back to exact match
		return pattern == action
	}

	return g.Match(action)
}

// MatchesResource checks if a resource pattern matches a specific resource ARN
// Supports AWS ARN wildcards: *, arn:aws:s3:::bucket/*, arn:aws:iam::*:role/*, etc.
func MatchesResource(pattern, arn string) bool {
	// Exact match (most common case)
	if pattern == arn {
		return true
	}

	// Universal wildcard
	if pattern == "*" {
		return true
	}

	// Compile glob pattern for ARN matching
	g, err := glob.Compile(pattern)
	if err != nil {
		// If pattern is invalid, fall back to exact match
		return pattern == arn
	}

	return g.Match(arn)
}

// MatchesNotAction checks if an action is NOT excluded by NotAction patterns
// Returns true if the action should be included (not in the exclusion list)
// Returns false if the action matches any NotAction pattern (should be excluded)
func MatchesNotAction(notActionPatterns []string, action string) bool {
	// For each pattern in NotAction:
	//   If pattern matches action, return false (action is excluded)
	// If no patterns match, return true (action is included)
	for _, pattern := range notActionPatterns {
		if MatchesAction(pattern, action) {
			return false // Action is excluded by NotAction
		}
	}
	return true // Action is not excluded
}

// MatchesNotResource checks if a resource is NOT excluded by NotResource patterns
// Returns true if the resource should be included (not in the exclusion list)
// Returns false if the resource matches any NotResource pattern (should be excluded)
func MatchesNotResource(notResourcePatterns []string, arn string) bool {
	// For each pattern in NotResource:
	//   If pattern matches resource, return false (resource is excluded)
	// If no patterns match, return true (resource is included)
	for _, pattern := range notResourcePatterns {
		if MatchesResource(pattern, arn) {
			return false // Resource is excluded by NotResource
		}
	}
	return true // Resource is not excluded
}

// EvaluateCondition evaluates a policy condition
// For MVP, this just detects if conditions exist
func EvaluateCondition(condition map[string]map[string]interface{}) (bool, []string) {
	if len(condition) == 0 {
		return true, nil
	}

	// For MVP, return true but list the conditions
	var warnings []string
	for condType, condMap := range condition {
		for condKey := range condMap {
			warnings = append(warnings, fmt.Sprintf("Condition: %s %s", condType, condKey))
		}
	}

	return true, warnings
}
