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

	// Get local account ID from first principal
	var localAccountID string
	for _, p := range e.graph.GetAllPrincipals() {
		if p.AccountID != "" {
			localAccountID = p.AccountID
			break
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
