package conditions

import (
	"fmt"
	"net"
	"strings"
)

// EvaluationContext contains runtime information for condition evaluation
type EvaluationContext struct {
	// Network context
	SourceIP string // IP address of the requester

	// Authentication context
	MFAAuthenticated bool   // Whether MFA was used
	PrincipalARN     string // ARN of the principal making the request
	PrincipalOrgID   string // Organization ID of the principal

	// Request context
	SecureTransport bool   // Whether request uses HTTPS
	RequestedRegion string // AWS region being accessed

	// Tag context
	PrincipalTags map[string]string // Tags on the principal
	ResourceTags  map[string]string // Tags on the resource
}

// NewDefaultContext creates a permissive default context
// This maintains MVP behavior: conditions pass by default
func NewDefaultContext() *EvaluationContext {
	return &EvaluationContext{
		SourceIP:         "0.0.0.0", // Permissive default
		MFAAuthenticated: false,
		SecureTransport:  true, // Assume HTTPS
		PrincipalTags:    make(map[string]string),
		ResourceTags:     make(map[string]string),
	}
}

// Evaluate evaluates AWS policy conditions against a context
// Returns (matched bool, error)
// All conditions must pass (implicit AND logic)
func Evaluate(condition map[string]map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	// Empty condition always passes
	if len(condition) == 0 {
		return true, nil
	}

	// Use default context if none provided (permissive behavior)
	if ctx == nil {
		ctx = NewDefaultContext()
	}

	// All condition operators must pass (AND logic)
	for operator, operands := range condition {
		matched, err := evaluateOperator(operator, operands, ctx)
		if err != nil {
			return false, fmt.Errorf("evaluating %s: %w", operator, err)
		}
		if !matched {
			return false, nil
		}
	}

	return true, nil
}

// evaluateOperator evaluates a single condition operator
func evaluateOperator(operator string, operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	switch operator {
	// String conditions
	case "StringEquals":
		return evaluateStringEquals(operands, ctx)
	case "StringNotEquals":
		return evaluateStringNotEquals(operands, ctx)
	case "StringLike":
		return evaluateStringLike(operands, ctx)

	// Boolean conditions
	case "Bool":
		return evaluateBool(operands, ctx)

	// IP address conditions
	case "IpAddress":
		return evaluateIPAddress(operands, ctx)
	case "NotIpAddress":
		result, err := evaluateIPAddress(operands, ctx)
		return !result, err

	// Numeric conditions (future implementation)
	case "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
		"NumericGreaterThan", "NumericGreaterThanEquals":
		return false, fmt.Errorf("numeric condition operators not yet implemented: %s", operator)

	// Date conditions (future implementation)
	case "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
		"DateGreaterThan", "DateGreaterThanEquals":
		return false, fmt.Errorf("date condition operators not yet implemented: %s", operator)

	// ARN conditions (future implementation)
	case "ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike":
		return false, fmt.Errorf("ARN condition operators not yet implemented: %s", operator)

	default:
		return false, fmt.Errorf("unsupported condition operator: %s", operator)
	}
}

// evaluateStringEquals checks if string values match
func evaluateStringEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue := getContextValue(key, ctx)
		if actualValue == "" {
			// Key not found in context - condition fails
			return false, nil
		}

		// Convert expected value to string
		expectedStr, ok := expectedValue.(string)
		if !ok {
			return false, fmt.Errorf("expected string value for StringEquals, got %T", expectedValue)
		}

		// Case-sensitive comparison
		if actualValue != expectedStr {
			return false, nil
		}
	}

	return true, nil
}

// evaluateStringNotEquals checks if string values don't match
func evaluateStringNotEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	result, err := evaluateStringEquals(operands, ctx)
	return !result, err
}

// evaluateStringLike checks if string matches a pattern (supports * wildcard)
func evaluateStringLike(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue := getContextValue(key, ctx)
		if actualValue == "" {
			return false, nil
		}

		expectedStr, ok := expectedValue.(string)
		if !ok {
			return false, fmt.Errorf("expected string value for StringLike, got %T", expectedValue)
		}

		// Simple wildcard matching (* matches any sequence)
		if !wildcardMatch(expectedStr, actualValue) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateBool checks boolean conditions
func evaluateBool(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue := getBoolContextValue(key, ctx)

		// Handle expected value as string "true"/"false" or bool
		var expectedBool bool
		switch v := expectedValue.(type) {
		case bool:
			expectedBool = v
		case string:
			expectedBool = strings.ToLower(v) == "true"
		default:
			return false, fmt.Errorf("expected bool or string value for Bool, got %T", expectedValue)
		}

		if actualValue != expectedBool {
			return false, nil
		}
	}

	return true, nil
}

// evaluateIPAddress checks if source IP matches CIDR block
func evaluateIPAddress(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		if key != "aws:SourceIp" {
			// Only aws:SourceIp is supported for IpAddress operator
			return false, fmt.Errorf("unsupported key for IpAddress: %s", key)
		}

		// Special case: "0.0.0.0" means permissive/default context (no restriction)
		// This allows backward compatibility with MVP behavior
		if ctx.SourceIP == "0.0.0.0" {
			// Permissive default - pass the condition
			return true, nil
		}

		if ctx.SourceIP == "" {
			// No source IP in context - condition fails
			return false, nil
		}

		// Parse expected CIDR block
		expectedCIDR, ok := expectedValue.(string)
		if !ok {
			return false, fmt.Errorf("expected string CIDR for IpAddress, got %T", expectedValue)
		}

		// Parse CIDR
		_, ipNet, err := net.ParseCIDR(expectedCIDR)
		if err != nil {
			// Try parsing as single IP and convert to /32 CIDR
			ip := net.ParseIP(expectedCIDR)
			if ip == nil {
				return false, fmt.Errorf("invalid IP or CIDR: %s", expectedCIDR)
			}
			// Single IP address - treat as /32
			if ip.To4() != nil {
				expectedCIDR = expectedCIDR + "/32"
			} else {
				expectedCIDR = expectedCIDR + "/128"
			}
			_, ipNet, err = net.ParseCIDR(expectedCIDR)
			if err != nil {
				return false, fmt.Errorf("failed to parse IP: %s", expectedCIDR)
			}
		}

		// Parse source IP
		sourceIP := net.ParseIP(ctx.SourceIP)
		if sourceIP == nil {
			return false, fmt.Errorf("invalid source IP in context: %s", ctx.SourceIP)
		}

		// Check if source IP is in CIDR block
		if !ipNet.Contains(sourceIP) {
			return false, nil
		}
	}

	return true, nil
}

// getContextValue retrieves a string value from context by key
func getContextValue(key string, ctx *EvaluationContext) string {
	switch key {
	case "aws:PrincipalOrgID":
		return ctx.PrincipalOrgID
	case "aws:PrincipalArn":
		return ctx.PrincipalARN
	case "aws:RequestedRegion":
		return ctx.RequestedRegion
	case "aws:SourceIp":
		return ctx.SourceIP
	default:
		// Check principal tags
		if strings.HasPrefix(key, "aws:PrincipalTag/") {
			tagKey := strings.TrimPrefix(key, "aws:PrincipalTag/")
			return ctx.PrincipalTags[tagKey]
		}
		// Check resource tags
		if strings.HasPrefix(key, "aws:ResourceTag/") {
			tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
			return ctx.ResourceTags[tagKey]
		}
		return ""
	}
}

// getBoolContextValue retrieves a boolean value from context by key
func getBoolContextValue(key string, ctx *EvaluationContext) bool {
	switch key {
	case "aws:MultiFactorAuthPresent":
		return ctx.MFAAuthenticated
	case "aws:SecureTransport":
		return ctx.SecureTransport
	default:
		return false
	}
}

// wildcardMatch performs simple wildcard matching (* matches any sequence)
func wildcardMatch(pattern, text string) bool {
	// Split pattern by *
	parts := strings.Split(pattern, "*")

	// If no wildcards, must be exact match
	if len(parts) == 1 {
		return pattern == text
	}

	// Check if text starts with first part
	if !strings.HasPrefix(text, parts[0]) {
		return false
	}
	text = text[len(parts[0]):]

	// Check if text ends with last part
	if !strings.HasSuffix(text, parts[len(parts)-1]) {
		return false
	}
	text = text[:len(text)-len(parts[len(parts)-1])]

	// Check middle parts appear in order
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(text, parts[i])
		if idx == -1 {
			return false
		}
		text = text[idx+len(parts[i]):]
	}

	return true
}
