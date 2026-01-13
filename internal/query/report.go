package query

import (
	"fmt"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// FindHighRiskAccess identifies high-risk access patterns
func (e *Engine) FindHighRiskAccess() ([]HighRiskFinding, error) {
	findings := make([]HighRiskFinding, 0)

	// Pattern 1: Admin access (wildcard permissions)
	adminFindings := e.findAdminAccess()
	findings = append(findings, adminFindings...)

	// Pattern 2: Public resource access
	publicFindings := e.findPublicResourceAccess()
	findings = append(findings, publicFindings...)

	// Pattern 3: Cross-account access
	crossAccountFindings := e.findCrossAccountAccess()
	findings = append(findings, crossAccountFindings...)

	// Pattern 4: Overly permissive S3 access
	s3Findings := e.findOverlyPermissiveS3Access()
	findings = append(findings, s3Findings...)

	// Pattern 5: Sensitive action access
	sensitiveFindings := e.findSensitiveActionAccess()
	findings = append(findings, sensitiveFindings...)

	// Pattern 6: Direct user policy attachments (CIS control 1.16)
	directPolicyFindings := e.findDirectUserPolicyAttachments()
	findings = append(findings, directPolicyFindings...)

	// Pattern 7: Overly permissive Lambda execution roles
	lambdaFindings := e.findOverlyPermissiveLambdaRoles()
	findings = append(findings, lambdaFindings...)

	// Pattern 8: Wildcard principals in resource policies
	wildcardResourceFindings := e.findWildcardResourcePolicies()
	findings = append(findings, wildcardResourceFindings...)

	// Pattern 9: Service role privilege escalation
	escalationFindings := e.findServiceRoleEscalation()
	findings = append(findings, escalationFindings...)

	// Pattern 10: Missing MFA for privileged users
	mfaFindings := e.findMissingMFAForPrivilegedUsers()
	findings = append(findings, mfaFindings...)

	// Pattern 11: Cross-region resource access
	crossRegionFindings := e.findCrossRegionAccess()
	findings = append(findings, crossRegionFindings...)

	// Pattern 12: Broad network access (missing IP restrictions)
	networkFindings := e.findBroadNetworkAccess()
	findings = append(findings, networkFindings...)

	// Pattern 13: Resources missing resource-based policies
	missingPolicyFindings := e.findResourcesWithoutPolicies()
	findings = append(findings, missingPolicyFindings...)

	return findings, nil
}

// findAdminAccess detects principals with unrestricted admin access
func (e *Engine) findAdminAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	// Check all principals for wildcard permissions
	for _, principal := range e.graph.GetAllPrincipals() {
		// Skip public principal (handled separately)
		if principal.Type == types.PrincipalTypePublic {
			continue
		}

		if e.graph.CanAccess(principal.ARN, "*", "*") {
			findings = append(findings, HighRiskFinding{
				Type:        "Admin Access",
				Severity:    "CRITICAL",
				Description: fmt.Sprintf("Principal '%s' has unrestricted admin access (Action: *, Resource: *)", principal.Name),
				Principal:   principal,
				Action:      "*",
			})
		}
	}

	return findings
}

// findPublicResourceAccess detects resources accessible by anonymous users
func (e *Engine) findPublicResourceAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	// Check for public principal
	publicPrincipal, ok := e.graph.GetPrincipal("*")
	if !ok {
		return findings
	}

	// Find all resources accessible by public principal
	for _, resource := range e.graph.GetAllResources() {
		// Check if public principal has any access to this resource
		hasPublicAccess := false
		var allowedActions []string

		// Check common actions
		commonActions := []string{"*", "s3:*", "s3:GetObject", "kms:Decrypt", "sqs:*", "sns:*", "secretsmanager:GetSecretValue"}
		for _, action := range commonActions {
			if e.graph.CanAccess(publicPrincipal.ARN, action, resource.ARN) {
				hasPublicAccess = true
				allowedActions = append(allowedActions, action)
			}
		}

		if hasPublicAccess {
			severity := "HIGH"
			// S3 and Secrets Manager public access is especially critical
			if resource.Type == types.ResourceTypeS3 || resource.Type == types.ResourceTypeSecretsManager {
				severity = "CRITICAL"
			}

			actionStr := "*"
			if len(allowedActions) > 0 {
				actionStr = allowedActions[0] // Show first action
				if len(allowedActions) > 1 {
					actionStr = fmt.Sprintf("%s (+%d more)", actionStr, len(allowedActions)-1)
				}
			}

			findings = append(findings, HighRiskFinding{
				Type:        "Public Access",
				Severity:    severity,
				Description: fmt.Sprintf("Resource '%s' (%s) allows public/anonymous access (Action: %s)", resource.Name, resource.Type, actionStr),
				Principal:   publicPrincipal,
				Resource:    resource,
				Action:      actionStr,
			})
		}
	}

	return findings
}

// findCrossAccountAccess detects principals from external AWS accounts
func (e *Engine) findCrossAccountAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	// Get local account ID by finding the most common account ID
	accountCounts := make(map[string]int)
	for _, p := range e.graph.GetAllPrincipals() {
		if p.AccountID != "" && p.Type != types.PrincipalTypePublic {
			accountCounts[p.AccountID]++
		}
	}

	// Find the account ID with the most principals (likely the local account)
	var localAccountID string
	maxCount := 0
	for accountID, count := range accountCounts {
		if count > maxCount {
			maxCount = count
			localAccountID = accountID
		}
	}

	if localAccountID == "" {
		return findings // Can't determine cross-account without knowing local account
	}

	// Check all principals for external account IDs
	for _, principal := range e.graph.GetAllPrincipals() {
		// Skip if no account ID or if it's the public principal
		if principal.AccountID == "" || principal.Type == types.PrincipalTypePublic {
			continue
		}

		if principal.AccountID != localAccountID {
			findings = append(findings, HighRiskFinding{
				Type:        "Cross-Account Access",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Principal '%s' from external account %s has access to resources", principal.Name, principal.AccountID),
				Principal:   principal,
			})
		}
	}

	return findings
}

// findOverlyPermissiveS3Access detects principals with broad S3 permissions
func (e *Engine) findOverlyPermissiveS3Access() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, principal := range e.graph.GetAllPrincipals() {
		// Skip public principal (handled separately)
		if principal.Type == types.PrincipalTypePublic {
			continue
		}

		// Check for s3:* on all resources
		if e.graph.CanAccess(principal.ARN, "s3:*", "*") {
			findings = append(findings, HighRiskFinding{
				Type:        "Overly Permissive S3 Access",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Principal '%s' has full S3 access on all buckets (s3:* on *)", principal.Name),
				Principal:   principal,
				Action:      "s3:*",
			})
		}
	}

	return findings
}

// findSensitiveActionAccess detects principals with access to sensitive actions
func (e *Engine) findSensitiveActionAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	sensitiveActions := map[string]string{
		"iam:*":                         "Full IAM access on all resources",
		"kms:Decrypt":                   "KMS decryption access on all keys",
		"secretsmanager:GetSecretValue": "Secrets retrieval access on all secrets",
		"sts:AssumeRole":                "Role assumption access on all roles",
	}

	for _, principal := range e.graph.GetAllPrincipals() {
		// Skip public principal (handled separately)
		if principal.Type == types.PrincipalTypePublic {
			continue
		}

		for action, description := range sensitiveActions {
			if e.graph.CanAccess(principal.ARN, action, "*") {
				findings = append(findings, HighRiskFinding{
					Type:        "Sensitive Action Access",
					Severity:    "HIGH",
					Description: fmt.Sprintf("Principal '%s' has %s", principal.Name, description),
					Principal:   principal,
					Action:      action,
				})
			}
		}
	}

	return findings
}

// findDirectUserPolicyAttachments detects users with directly attached policies (CIS 1.16)
// Best practice: attach policies to groups/roles, not individual users
func (e *Engine) findDirectUserPolicyAttachments() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, principal := range e.graph.GetAllPrincipals() {
		// Only check IAM users (not roles or groups)
		if principal.Type != types.PrincipalTypeUser {
			continue
		}

		// Check if user has directly attached policies
		if len(principal.Policies) > 0 {
			findings = append(findings, HighRiskFinding{
				Type:        "Direct User Policy Attachment",
				Severity:    "LOW",
				Description: fmt.Sprintf("User '%s' has %d policies directly attached (CIS 1.16: attach policies to groups instead)", principal.Name, len(principal.Policies)),
				Principal:   principal,
			})
		}
	}

	return findings
}

// findOverlyPermissiveLambdaRoles detects Lambda execution roles with excessive permissions
func (e *Engine) findOverlyPermissiveLambdaRoles() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, principal := range e.graph.GetAllPrincipals() {
		// Only check roles (Lambda uses execution roles)
		if principal.Type != types.PrincipalTypeRole {
			continue
		}

		// Check if this looks like a Lambda execution role (common naming patterns)
		isLambdaRole := false
		for _, pattern := range []string{"lambda", "Lambda", "LAMBDA"} {
			if len(principal.Name) > 0 && containsIgnoreCase(principal.Name, pattern) {
				isLambdaRole = true
				break
			}
		}

		if !isLambdaRole {
			continue
		}

		// Check for overly permissive access
		if e.graph.CanAccess(principal.ARN, "*", "*") {
			findings = append(findings, HighRiskFinding{
				Type:        "Overly Permissive Lambda Role",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Lambda execution role '%s' has full admin access (*:* on *)", principal.Name),
				Principal:   principal,
				Action:      "*",
			})
		} else if e.graph.CanAccess(principal.ARN, "iam:*", "*") {
			findings = append(findings, HighRiskFinding{
				Type:        "Overly Permissive Lambda Role",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Lambda execution role '%s' has full IAM access", principal.Name),
				Principal:   principal,
				Action:      "iam:*",
			})
		} else if e.graph.CanAccess(principal.ARN, "s3:*", "*") {
			findings = append(findings, HighRiskFinding{
				Type:        "Overly Permissive Lambda Role",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Lambda execution role '%s' has full S3 access on all buckets", principal.Name),
				Principal:   principal,
				Action:      "s3:*",
			})
		}
	}

	return findings
}

// findWildcardResourcePolicies detects resource policies with wildcard principals
func (e *Engine) findWildcardResourcePolicies() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, resource := range e.graph.GetAllResources() {
		// Only check resources that can have resource policies
		if resource.ResourcePolicy == nil {
			continue
		}

		// Check each statement in the resource policy
		hasWildcardPrincipal := false
		for _, stmt := range resource.ResourcePolicy.Statements {
			// Check if Principal is "*" or contains "*"
			switch p := stmt.Principal.(type) {
			case string:
				if p == "*" {
					hasWildcardPrincipal = true
				}
			case map[string]interface{}:
				// Principal can be {"AWS": "*"} or {"AWS": ["arn1", "*"]}
				for _, value := range p {
					switch v := value.(type) {
					case string:
						if v == "*" {
							hasWildcardPrincipal = true
						}
					case []interface{}:
						for _, item := range v {
							if str, ok := item.(string); ok && str == "*" {
								hasWildcardPrincipal = true
							}
						}
					}
				}
			}

			if hasWildcardPrincipal {
				break
			}
		}

		if hasWildcardPrincipal {
			severity := "HIGH"
			if resource.Type == types.ResourceTypeS3 || resource.Type == types.ResourceTypeSecretsManager {
				severity = "CRITICAL"
			}

			findings = append(findings, HighRiskFinding{
				Type:        "Wildcard Resource Policy",
				Severity:    severity,
				Description: fmt.Sprintf("Resource '%s' (%s) has resource policy with wildcard principal (*)", resource.Name, resource.Type),
				Resource:    resource,
			})
		}
	}

	return findings
}

// findServiceRoleEscalation detects service roles that can escalate privileges
func (e *Engine) findServiceRoleEscalation() []HighRiskFinding {
	var findings []HighRiskFinding

	// Privilege escalation actions
	escalationActions := []string{
		"iam:CreateRole",
		"iam:AttachRolePolicy",
		"iam:PutRolePolicy",
		"iam:PassRole",
		"iam:CreateUser",
		"iam:AttachUserPolicy",
		"iam:PutUserPolicy",
	}

	for _, principal := range e.graph.GetAllPrincipals() {
		// Only check roles (service accounts)
		if principal.Type != types.PrincipalTypeRole {
			continue
		}

		// Check if role has any privilege escalation actions
		var foundActions []string
		for _, action := range escalationActions {
			if e.graph.CanAccess(principal.ARN, action, "*") {
				foundActions = append(foundActions, action)
			}
		}

		if len(foundActions) > 0 {
			actionStr := foundActions[0]
			if len(foundActions) > 1 {
				actionStr = fmt.Sprintf("%s (+%d more)", actionStr, len(foundActions)-1)
			}

			findings = append(findings, HighRiskFinding{
				Type:        "Service Role Privilege Escalation",
				Severity:    "HIGH",
				Description: fmt.Sprintf("Role '%s' can escalate privileges via IAM actions: %s", principal.Name, actionStr),
				Principal:   principal,
				Action:      actionStr,
			})
		}
	}

	return findings
}

// findMissingMFAForPrivilegedUsers detects privileged users without MFA requirements
func (e *Engine) findMissingMFAForPrivilegedUsers() []HighRiskFinding {
	var findings []HighRiskFinding

	// Define privileged actions that should require MFA
	privilegedActions := []string{"*", "iam:*", "s3:Delete*", "kms:*", "secretsmanager:*"}

	for _, principal := range e.graph.GetAllPrincipals() {
		// Only check IAM users (MFA is for human users)
		if principal.Type != types.PrincipalTypeUser {
			continue
		}

		// Check if user has access to privileged actions
		hasPrivilegedAccess := false
		for _, action := range privilegedActions {
			if e.graph.CanAccess(principal.ARN, action, "*", e.context) {
				hasPrivilegedAccess = true
				break
			}
		}

		if !hasPrivilegedAccess {
			continue
		}

		// Check if any of the user's policies have MFA conditions
		hasMFACondition := false
		for _, policy := range principal.Policies {
			for _, stmt := range policy.Statements {
				if stmt.Condition != nil {
					// Check for Bool: aws:MultiFactorAuthPresent
					if boolCond, ok := stmt.Condition["Bool"]; ok {
						if mfaVal, ok := boolCond["aws:MultiFactorAuthPresent"]; ok {
							if mfaBool, ok := mfaVal.(bool); ok && mfaBool {
								hasMFACondition = true
							} else if mfaStr, ok := mfaVal.(string); ok && mfaStr == "true" {
								hasMFACondition = true
							}
						}
					}
				}

				if hasMFACondition {
					break
				}
			}
			if hasMFACondition {
				break
			}
		}

		if !hasMFACondition {
			findings = append(findings, HighRiskFinding{
				Type:        "Missing MFA for Privileged User",
				Severity:    "MEDIUM",
				Description: fmt.Sprintf("Privileged user '%s' does not require MFA authentication", principal.Name),
				Principal:   principal,
			})
		}
	}

	return findings
}

// findCrossRegionAccess detects principals accessing resources in different regions
func (e *Engine) findCrossRegionAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	// Extract region from ARN: arn:aws:service:region:account:resource
	extractRegion := func(arn string) string {
		parts := splitARN(arn)
		if len(parts) >= 4 {
			return parts[3]
		}
		return ""
	}

	// Track principal regions (based on their ARN)
	principalRegions := make(map[string]string)
	for _, principal := range e.graph.GetAllPrincipals() {
		if principal.Type == types.PrincipalTypePublic {
			continue
		}
		region := extractRegion(principal.ARN)
		if region != "" {
			principalRegions[principal.ARN] = region
		}
	}

	// Check if principals access resources in different regions
	for _, resource := range e.graph.GetAllResources() {
		resourceRegion := extractRegion(resource.ARN)
		if resourceRegion == "" {
			continue // Skip global resources or resources without region
		}

		// Find principals that can access this resource
		for _, principal := range e.graph.GetAllPrincipals() {
			if principal.Type == types.PrincipalTypePublic {
				continue
			}

			principalRegion := principalRegions[principal.ARN]
			if principalRegion == "" || principalRegion == resourceRegion {
				continue // Same region or no region info
			}

			// Check if principal has access to this resource
			if e.graph.CanAccess(principal.ARN, "*", resource.ARN, e.context) ||
				e.graph.CanAccess(principal.ARN, "s3:*", resource.ARN, e.context) {

				findings = append(findings, HighRiskFinding{
					Type:        "Cross-Region Resource Access",
					Severity:    "LOW",
					Description: fmt.Sprintf("Principal '%s' (%s) accesses resource '%s' (%s) - potential data sovereignty concern", principal.Name, principalRegion, resource.Name, resourceRegion),
					Principal:   principal,
					Resource:    resource,
				})
			}
		}
	}

	return findings
}

// findBroadNetworkAccess detects resources without IP address restrictions
func (e *Engine) findBroadNetworkAccess() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, resource := range e.graph.GetAllResources() {
		// Only check S3 buckets and API Gateway APIs (commonly have IP restrictions)
		if resource.Type != types.ResourceTypeS3 && resource.Type != types.ResourceTypeAPIGateway {
			continue
		}

		if resource.ResourcePolicy == nil {
			continue
		}

		// Check if any statement has IP address conditions
		hasIPRestriction := false
		for _, stmt := range resource.ResourcePolicy.Statements {
			if stmt.Effect == types.EffectAllow && stmt.Condition != nil {
				// Check for IpAddress or NotIpAddress conditions
				if _, ok := stmt.Condition["IpAddress"]; ok {
					hasIPRestriction = true
					break
				}
				if _, ok := stmt.Condition["NotIpAddress"]; ok {
					hasIPRestriction = true
					break
				}
			}
		}

		// If resource policy allows access without IP restrictions, flag it
		if !hasIPRestriction {
			// Check if resource has public access
			hasPublicAccess := false
			for _, stmt := range resource.ResourcePolicy.Statements {
				if stmt.Effect == types.EffectAllow {
					switch p := stmt.Principal.(type) {
					case string:
						if p == "*" {
							hasPublicAccess = true
						}
					case map[string]interface{}:
						for _, value := range p {
							if str, ok := value.(string); ok && str == "*" {
								hasPublicAccess = true
							}
						}
					}
				}
			}

			if hasPublicAccess {
				findings = append(findings, HighRiskFinding{
					Type:        "Broad Network Access",
					Severity:    "MEDIUM",
					Description: fmt.Sprintf("Resource '%s' (%s) allows public access without IP address restrictions", resource.Name, resource.Type),
					Resource:    resource,
				})
			}
		}
	}

	return findings
}

// findResourcesWithoutPolicies detects resources that should have resource-based policies
func (e *Engine) findResourcesWithoutPolicies() []HighRiskFinding {
	var findings []HighRiskFinding

	for _, resource := range e.graph.GetAllResources() {
		// Only check resource types that commonly use resource-based policies
		requiresPolicy := false
		switch resource.Type {
		case types.ResourceTypeKMS, types.ResourceTypeSecretsManager:
			// KMS keys and Secrets Manager secrets should always have resource policies
			requiresPolicy = true
		case types.ResourceTypeS3:
			// S3 buckets commonly have resource policies (but not required)
			requiresPolicy = true
		}

		if !requiresPolicy {
			continue
		}

		if resource.ResourcePolicy == nil || len(resource.ResourcePolicy.Statements) == 0 {
			severity := "LOW"
			if resource.Type == types.ResourceTypeKMS || resource.Type == types.ResourceTypeSecretsManager {
				severity = "MEDIUM" // Higher severity for sensitive resources
			}

			findings = append(findings, HighRiskFinding{
				Type:        "Missing Resource-Based Policy",
				Severity:    severity,
				Description: fmt.Sprintf("Resource '%s' (%s) lacks resource-based policy for defense-in-depth", resource.Name, resource.Type),
				Resource:    resource,
			})
		}
	}

	return findings
}

// Helper function to check if string contains substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	sLower := ""
	substrLower := ""
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			sLower += string(r + 32)
		} else {
			sLower += string(r)
		}
	}
	for _, r := range substr {
		if r >= 'A' && r <= 'Z' {
			substrLower += string(r + 32)
		} else {
			substrLower += string(r)
		}
	}
	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

// Helper function to split ARN into parts
func splitARN(arn string) []string {
	result := make([]string, 0)
	current := ""
	for _, r := range arn {
		if r == ':' {
			result = append(result, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	result = append(result, current)
	return result
}
