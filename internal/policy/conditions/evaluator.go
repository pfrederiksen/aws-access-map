package conditions

import (
	"fmt"
	"net"
	"strings"
	"time"
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

	// Numeric context
	NumericContext map[string]float64 // Numeric values for comparison (e.g., s3:max-keys, ec2:InstanceCount)

	// Date context
	CurrentTime time.Time             // Current request time (for date comparisons)
	DateContext map[string]time.Time // Date values for comparison (e.g., aws:CurrentTime, custom dates)
}

// NewDefaultContext creates a permissive default context
// This maintains MVP behavior: conditions pass by default
func NewDefaultContext() *EvaluationContext {
	return &EvaluationContext{
		SourceIP:         "0.0.0.0", // Permissive default
		MFAAuthenticated: false,
		SecureTransport:  true,      // Assume HTTPS
		PrincipalTags:    make(map[string]string),
		ResourceTags:     make(map[string]string),
		NumericContext:   make(map[string]float64),
		CurrentTime:      time.Now(), // Default to current time
		DateContext:      make(map[string]time.Time),
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

	// Numeric conditions
	case "NumericEquals":
		return evaluateNumericEquals(operands, ctx)
	case "NumericNotEquals":
		result, err := evaluateNumericEquals(operands, ctx)
		return !result, err
	case "NumericLessThan":
		return evaluateNumericLessThan(operands, ctx)
	case "NumericLessThanEquals":
		return evaluateNumericLessThanEquals(operands, ctx)
	case "NumericGreaterThan":
		return evaluateNumericGreaterThan(operands, ctx)
	case "NumericGreaterThanEquals":
		return evaluateNumericGreaterThanEquals(operands, ctx)

	// Date conditions
	case "DateEquals":
		return evaluateDateEquals(operands, ctx)
	case "DateNotEquals":
		result, err := evaluateDateEquals(operands, ctx)
		return !result, err
	case "DateLessThan":
		return evaluateDateLessThan(operands, ctx)
	case "DateLessThanEquals":
		return evaluateDateLessThanEquals(operands, ctx)
	case "DateGreaterThan":
		return evaluateDateGreaterThan(operands, ctx)
	case "DateGreaterThanEquals":
		return evaluateDateGreaterThanEquals(operands, ctx)

	// ARN conditions
	case "ArnEquals":
		return evaluateArnEquals(operands, ctx)
	case "ArnNotEquals":
		result, err := evaluateArnEquals(operands, ctx)
		return !result, err
	case "ArnLike":
		return evaluateArnLike(operands, ctx)
	case "ArnNotLike":
		result, err := evaluateArnLike(operands, ctx)
		return !result, err

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

// evaluateNumericEquals checks if numeric values are equal
func evaluateNumericEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue, ok := ctx.NumericContext[key]
		if !ok {
			// Key not found in context - condition fails
			return false, nil
		}

		// Convert expected value to float64
		expectedNum, err := toFloat64(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected numeric value for NumericEquals, got %T: %w", expectedValue, err)
		}

		if actualValue != expectedNum {
			return false, nil
		}
	}

	return true, nil
}

// evaluateNumericLessThan checks if actual value is less than expected
func evaluateNumericLessThan(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue, ok := ctx.NumericContext[key]
		if !ok {
			return false, nil
		}

		expectedNum, err := toFloat64(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected numeric value for NumericLessThan, got %T: %w", expectedValue, err)
		}

		if !(actualValue < expectedNum) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateNumericLessThanEquals checks if actual value is less than or equal to expected
func evaluateNumericLessThanEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue, ok := ctx.NumericContext[key]
		if !ok {
			return false, nil
		}

		expectedNum, err := toFloat64(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected numeric value for NumericLessThanEquals, got %T: %w", expectedValue, err)
		}

		if !(actualValue <= expectedNum) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateNumericGreaterThan checks if actual value is greater than expected
func evaluateNumericGreaterThan(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue, ok := ctx.NumericContext[key]
		if !ok {
			return false, nil
		}

		expectedNum, err := toFloat64(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected numeric value for NumericGreaterThan, got %T: %w", expectedValue, err)
		}

		if !(actualValue > expectedNum) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateNumericGreaterThanEquals checks if actual value is greater than or equal to expected
func evaluateNumericGreaterThanEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualValue, ok := ctx.NumericContext[key]
		if !ok {
			return false, nil
		}

		expectedNum, err := toFloat64(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected numeric value for NumericGreaterThanEquals, got %T: %w", expectedValue, err)
		}

		if !(actualValue >= expectedNum) {
			return false, nil
		}
	}

	return true, nil
}

// toFloat64 converts various numeric types to float64
func toFloat64(v interface{}) (float64, error) {
	switch val := v.(type) {
	case float64:
		return val, nil
	case float32:
		return float64(val), nil
	case int:
		return float64(val), nil
	case int32:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case string:
		// Try parsing string as number
		var num float64
		_, err := fmt.Sscanf(val, "%f", &num)
		if err != nil {
			return 0, fmt.Errorf("failed to parse string as number: %w", err)
		}
		return num, nil
	default:
		return 0, fmt.Errorf("unsupported numeric type: %T", v)
	}
}

// evaluateDateEquals checks if date values are equal
func evaluateDateEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualTime, err := getDateContextValue(key, ctx)
		if err != nil {
			return false, err
		}

		expectedTime, err := parseTime(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected date value for DateEquals, got %T: %w", expectedValue, err)
		}

		// Compare times (equal means same instant, ignoring location)
		if !actualTime.Equal(expectedTime) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateDateLessThan checks if actual time is before expected time
func evaluateDateLessThan(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualTime, err := getDateContextValue(key, ctx)
		if err != nil {
			return false, err
		}

		expectedTime, err := parseTime(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected date value for DateLessThan, got %T: %w", expectedValue, err)
		}

		if !actualTime.Before(expectedTime) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateDateLessThanEquals checks if actual time is before or equal to expected time
func evaluateDateLessThanEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualTime, err := getDateContextValue(key, ctx)
		if err != nil {
			return false, err
		}

		expectedTime, err := parseTime(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected date value for DateLessThanEquals, got %T: %w", expectedValue, err)
		}

		if !(actualTime.Before(expectedTime) || actualTime.Equal(expectedTime)) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateDateGreaterThan checks if actual time is after expected time
func evaluateDateGreaterThan(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualTime, err := getDateContextValue(key, ctx)
		if err != nil {
			return false, err
		}

		expectedTime, err := parseTime(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected date value for DateGreaterThan, got %T: %w", expectedValue, err)
		}

		if !actualTime.After(expectedTime) {
			return false, nil
		}
	}

	return true, nil
}

// evaluateDateGreaterThanEquals checks if actual time is after or equal to expected time
func evaluateDateGreaterThanEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualTime, err := getDateContextValue(key, ctx)
		if err != nil {
			return false, err
		}

		expectedTime, err := parseTime(expectedValue)
		if err != nil {
			return false, fmt.Errorf("expected date value for DateGreaterThanEquals, got %T: %w", expectedValue, err)
		}

		if !(actualTime.After(expectedTime) || actualTime.Equal(expectedTime)) {
			return false, nil
		}
	}

	return true, nil
}

// getDateContextValue retrieves a time value from context by key
func getDateContextValue(key string, ctx *EvaluationContext) (time.Time, error) {
	// Check if key is in DateContext map
	if t, ok := ctx.DateContext[key]; ok {
		return t, nil
	}

	// Special key: aws:CurrentTime uses the context's CurrentTime
	if key == "aws:CurrentTime" || key == "aws:EpochTime" {
		if ctx.CurrentTime.IsZero() {
			return time.Time{}, fmt.Errorf("current time not set in context for key: %s", key)
		}
		return ctx.CurrentTime, nil
	}

	return time.Time{}, fmt.Errorf("date key not found in context: %s", key)
}

// parseTime parses various time formats into time.Time
func parseTime(v interface{}) (time.Time, error) {
	switch val := v.(type) {
	case time.Time:
		return val, nil
	case string:
		// Try multiple AWS-compatible time formats
		formats := []string{
			time.RFC3339,                // 2006-01-02T15:04:05Z07:00
			"2006-01-02T15:04:05Z",      // ISO 8601 with Z
			"2006-01-02T15:04:05",       // ISO 8601 without timezone
			"2006-01-02",                // Date only
			time.RFC1123,                // RFC 1123
			time.RFC1123Z,               // RFC 1123 with numeric zone
		}

		for _, format := range formats {
			if t, err := time.Parse(format, val); err == nil {
				return t, nil
			}
		}

		return time.Time{}, fmt.Errorf("failed to parse time string: %s", val)
	case int64:
		// Unix timestamp (seconds since epoch)
		return time.Unix(val, 0), nil
	case int:
		return time.Unix(int64(val), 0), nil
	case float64:
		// Unix timestamp as float (might have milliseconds)
		return time.Unix(int64(val), 0), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported time type: %T", v)
	}
}

// evaluateArnEquals checks if ARN values match exactly
func evaluateArnEquals(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualARN := getARNContextValue(key, ctx)
		if actualARN == "" {
			// Key not found in context - condition fails
			return false, nil
		}

		// Convert expected value to string
		expectedARN, ok := expectedValue.(string)
		if !ok {
			return false, fmt.Errorf("expected string ARN for ArnEquals, got %T", expectedValue)
		}

		// Case-sensitive exact match
		if actualARN != expectedARN {
			return false, nil
		}
	}

	return true, nil
}

// evaluateArnLike checks if ARN matches a pattern (supports * and ? wildcards)
func evaluateArnLike(operands map[string]interface{}, ctx *EvaluationContext) (bool, error) {
	for key, expectedValue := range operands {
		actualARN := getARNContextValue(key, ctx)
		if actualARN == "" {
			return false, nil
		}

		expectedPattern, ok := expectedValue.(string)
		if !ok {
			return false, fmt.Errorf("expected string pattern for ArnLike, got %T", expectedValue)
		}

		// Use wildcard matching for ARN patterns
		if !wildcardMatch(expectedPattern, actualARN) {
			return false, nil
		}
	}

	return true, nil
}

// getARNContextValue retrieves an ARN value from context by key
func getARNContextValue(key string, ctx *EvaluationContext) string {
	switch key {
	case "aws:SourceArn":
		// Source ARN would be set in context for cross-service requests
		// For now, return empty (could be extended)
		return ""
	case "aws:PrincipalArn":
		return ctx.PrincipalARN
	default:
		// Unknown ARN key
		return ""
	}
}
