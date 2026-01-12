package policy

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/yourusername/aws-access-map/pkg/types"
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
func MatchesAction(pattern, action string) bool {
	// Simple wildcard matching for MVP
	// TODO: Implement full wildcard matching (s3:Get*, s3:*)
	if pattern == "*" || pattern == action {
		return true
	}

	// Basic prefix matching for patterns like "s3:Get*"
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(action) >= len(prefix) && action[:len(prefix)] == prefix
	}

	return false
}

// MatchesResource checks if a resource pattern matches a specific resource ARN
func MatchesResource(pattern, arn string) bool {
	// Simple wildcard matching for MVP
	// TODO: Implement full ARN wildcard matching
	if pattern == "*" || pattern == arn {
		return true
	}

	// Basic suffix matching for patterns like "arn:aws:s3:::bucket/*"
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(arn) >= len(prefix) && arn[:len(prefix)] == prefix
	}

	return false
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
