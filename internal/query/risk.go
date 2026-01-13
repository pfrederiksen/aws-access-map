package query

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// RiskScore represents a quantitative risk assessment for a finding
type RiskScore struct {
	Finding    HighRiskFinding
	Impact     float64 // 0-10: potential damage if exploited
	Likelihood float64 // 0-10: probability of exploitation
	Multiplier float64 // 1.0-2.0: privilege amplification factor
	TotalScore float64 // 0-10: final risk score (capped at 10)
	Severity   string  // CRITICAL/HIGH/MEDIUM/LOW/INFO based on score
}

// RiskContext provides additional metadata for risk scoring
type RiskContext struct {
	AccountID       string
	AdminPrincipals map[string]bool              // Principals with admin access
	TaggedResources map[string]map[string]string // Resource ARN -> tags
}

// RiskSummary provides aggregated risk metrics
type RiskSummary struct {
	TotalFindings    int
	CriticalFindings int
	HighFindings     int
	MediumFindings   int
	LowFindings      int
	InfoFindings     int
	AverageRiskScore float64
	TopRisks         []RiskScore // Top 10 by score
	RiskDistribution map[string]int
}

// CalculateRiskScore computes a quantitative risk score for a finding
// Formula: Risk = Impact × (Likelihood / 10) × Multiplier, capped at 10.0
func CalculateRiskScore(finding HighRiskFinding, context RiskContext) RiskScore {
	impact := calculateImpact(finding, context)
	likelihood := calculateLikelihood(finding, context)
	multiplier := calculatePrivilegeMultiplier(finding, context)

	// Compute total score: impact × (likelihood normalized) × multiplier
	totalScore := math.Min(10.0, impact*(likelihood/10.0)*multiplier)

	return RiskScore{
		Finding:    finding,
		Impact:     impact,
		Likelihood: likelihood,
		Multiplier: multiplier,
		TotalScore: totalScore,
		Severity:   mapScoreToSeverity(totalScore),
	}
}

// calculateImpact determines potential damage based on action and resource
func calculateImpact(finding HighRiskFinding, context RiskContext) float64 {
	impact := 5.0 // Default medium impact

	action := finding.Action
	resource := finding.Resource

	// Base impact by action type
	if action == "*" {
		impact = 10.0 // Full wildcard = maximum impact
	} else if strings.HasPrefix(action, "iam:Delete") || strings.HasPrefix(action, "s3:Delete") {
		impact = 8.0 // Deletion actions
	} else if strings.Contains(action, "Delete") {
		impact = 7.0 // Other delete operations
	} else if strings.Contains(action, "Put") || strings.Contains(action, "Create") {
		impact = 6.0 // Write operations
	} else if action == "kms:Decrypt" || action == "secretsmanager:GetSecretValue" {
		impact = 7.0 // Sensitive data access
	} else if strings.Contains(action, "Get") {
		impact = 4.0 // Read operations
	} else if strings.Contains(action, "List") || strings.Contains(action, "Describe") {
		impact = 2.0 // Enumeration operations
	}

	// Check for IAM actions (high impact)
	if strings.HasPrefix(action, "iam:") {
		if action == "iam:*" {
			impact = 9.0
		} else if strings.Contains(action, "Create") || strings.Contains(action, "Attach") || strings.Contains(action, "Put") {
			impact = math.Max(impact, 7.0)
		}
	}

	// Apply resource sensitivity multiplier
	if resource != nil {
		// Check resource type
		switch resource.Type {
		case types.ResourceTypeSecretsManager:
			impact *= 1.8 // Secrets are highly sensitive
		case types.ResourceTypeKMS:
			impact *= 1.5 // Encryption keys are sensitive
		case types.ResourceTypeS3:
			// Future: Check for production or PII tags from context.TaggedResources
			// For now, apply moderate multiplier for all S3 resources
			impact *= 1.2
		}
	}

	// Cap at 10.0
	return math.Min(10.0, impact)
}

// calculateLikelihood determines probability of exploitation
func calculateLikelihood(finding HighRiskFinding, context RiskContext) float64 {
	likelihood := 5.0 // Default medium likelihood

	// Finding type determines baseline likelihood
	switch finding.Type {
	case "Public Access":
		likelihood = 10.0 // Public = very high likelihood
	case "Wildcard Resource Policy":
		likelihood = 9.0 // Wildcard principal = near-public
	case "Admin Access":
		likelihood = 7.0 // Admin access = high value target
	case "Cross-Account Access":
		likelihood = 8.0 // External access = high likelihood
	case "Overly Permissive S3 Access", "Overly Permissive Lambda Role":
		likelihood = 6.0 // Broad permissions
	case "Sensitive Action Access":
		likelihood = 6.0 // High value actions
	case "Service Role Privilege Escalation":
		likelihood = 7.0 // Direct escalation path
	case "Missing MFA for Privileged User":
		likelihood = 5.0 // Depends on other controls
	case "Broad Network Access":
		likelihood = 7.0 // No IP restrictions = accessible from anywhere
	case "Direct User Policy Attachment":
		likelihood = 3.0 // Low security risk, mostly compliance
	case "Missing Resource-Based Policy":
		likelihood = 4.0 // Defense-in-depth gap
	case "Cross-Region Resource Access":
		likelihood = 2.0 // Low security risk, mostly data sovereignty
	default:
		likelihood = 5.0
	}

	// Adjust based on severity (correlation with likelihood)
	switch finding.Severity {
	case "CRITICAL":
		likelihood = math.Max(likelihood, 9.0)
	case "HIGH":
		likelihood = math.Max(likelihood, 7.0)
	case "MEDIUM":
		likelihood = math.Max(likelihood, 5.0)
	case "LOW":
		likelihood = math.Min(likelihood, 4.0)
	}

	return likelihood
}

// calculatePrivilegeMultiplier determines amplification based on principal privileges
func calculatePrivilegeMultiplier(finding HighRiskFinding, context RiskContext) float64 {
	multiplier := 1.0

	if finding.Principal == nil {
		return multiplier
	}

	// Check if principal has admin access elsewhere
	if context.AdminPrincipals[finding.Principal.ARN] {
		multiplier = 1.5 // Admin elsewhere = higher risk
	}

	// Service roles get slightly higher multiplier (long-lived credentials)
	if finding.Principal.Type == types.PrincipalTypeRole {
		multiplier = math.Max(multiplier, 1.2)
	}

	// Public principal gets maximum multiplier
	if finding.Principal.Type == types.PrincipalTypePublic {
		multiplier = 2.0
	}

	return multiplier
}

// mapScoreToSeverity converts numeric score to severity label
func mapScoreToSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else if score >= 1.0 {
		return "LOW"
	}
	return "INFO"
}

// GenerateRiskSummary creates aggregated risk metrics from findings
func GenerateRiskSummary(findings []HighRiskFinding, context RiskContext) RiskSummary {
	var scores []RiskScore
	var totalScore float64

	// Calculate risk score for each finding
	for _, finding := range findings {
		score := CalculateRiskScore(finding, context)
		scores = append(scores, score)
		totalScore += score.TotalScore
	}

	// Count by severity
	summary := RiskSummary{
		TotalFindings:    len(scores),
		RiskDistribution: make(map[string]int),
	}

	for _, score := range scores {
		switch score.Severity {
		case "CRITICAL":
			summary.CriticalFindings++
		case "HIGH":
			summary.HighFindings++
		case "MEDIUM":
			summary.MediumFindings++
		case "LOW":
			summary.LowFindings++
		case "INFO":
			summary.InfoFindings++
		}
		summary.RiskDistribution[score.Severity]++
	}

	// Calculate average
	if len(scores) > 0 {
		summary.AverageRiskScore = totalScore / float64(len(scores))
	}

	// Sort by score descending, take top 10
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].TotalScore > scores[j].TotalScore
	})

	if len(scores) > 10 {
		summary.TopRisks = scores[:10]
	} else {
		summary.TopRisks = scores
	}

	return summary
}

// BuildRiskContext creates a RiskContext from the graph
func (e *Engine) BuildRiskContext() RiskContext {
	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	// Identify admin principals
	for _, principal := range e.graph.GetAllPrincipals() {
		if principal.Type == types.PrincipalTypePublic {
			continue
		}
		if e.graph.CanAccess(principal.ARN, "*", "*", e.context) {
			context.AdminPrincipals[principal.ARN] = true
		}
	}

	// Future: Collect resource tags when Resource type includes Tags field
	// For now, TaggedResources remains empty

	return context
}

// GetRiskScores calculates risk scores for all findings
func (e *Engine) GetRiskScores() ([]RiskScore, error) {
	// Get all high-risk findings
	findings, err := e.FindHighRiskAccess()
	if err != nil {
		return nil, fmt.Errorf("failed to find high-risk access: %w", err)
	}

	// Build risk context
	context := e.BuildRiskContext()

	// Calculate risk scores
	var scores []RiskScore
	for _, finding := range findings {
		score := CalculateRiskScore(finding, context)
		scores = append(scores, score)
	}

	// Sort by total score descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].TotalScore > scores[j].TotalScore
	})

	return scores, nil
}

// GetRiskSummary generates a summary of all risks
func (e *Engine) GetRiskSummary() (RiskSummary, error) {
	findings, err := e.FindHighRiskAccess()
	if err != nil {
		return RiskSummary{}, fmt.Errorf("failed to find high-risk access: %w", err)
	}

	context := e.BuildRiskContext()
	return GenerateRiskSummary(findings, context), nil
}
