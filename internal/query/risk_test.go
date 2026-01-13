package query

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestCalculateRiskScore_AdminAccess(t *testing.T) {
	finding := HighRiskFinding{
		Type:        "Admin Access",
		Severity:    "CRITICAL",
		Description: "User has full admin access",
		Principal: &types.Principal{
			ARN:  "arn:aws:iam::123456789012:user/admin",
			Type: types.PrincipalTypeUser,
			Name: "admin",
		},
		Action: "*",
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	score := CalculateRiskScore(finding, context)

	// Admin access should have high impact and likelihood
	if score.Impact < 9.0 {
		t.Errorf("Expected high impact for admin access, got %.2f", score.Impact)
	}

	if score.Likelihood < 7.0 {
		t.Errorf("Expected high likelihood for admin access, got %.2f", score.Likelihood)
	}

	if score.Severity != "CRITICAL" && score.Severity != "HIGH" {
		t.Errorf("Expected CRITICAL or HIGH severity, got %s", score.Severity)
	}

	if score.TotalScore <= 0 {
		t.Error("Total score should be greater than 0")
	}

	if score.TotalScore > 10.0 {
		t.Errorf("Total score should be capped at 10.0, got %.2f", score.TotalScore)
	}
}

func TestCalculateRiskScore_PublicAccess(t *testing.T) {
	finding := HighRiskFinding{
		Type:        "Public Access",
		Severity:    "CRITICAL",
		Description: "S3 bucket allows public access",
		Principal: &types.Principal{
			ARN:  "*",
			Type: types.PrincipalTypePublic,
			Name: "Public (Anonymous)",
		},
		Resource: &types.Resource{
			ARN:  "arn:aws:s3:::public-bucket",
			Type: types.ResourceTypeS3,
			Name: "public-bucket",
		},
		Action: "s3:GetObject",
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	score := CalculateRiskScore(finding, context)

	// Public access should have maximum likelihood
	if score.Likelihood != 10.0 {
		t.Errorf("Expected maximum likelihood (10.0) for public access, got %.2f", score.Likelihood)
	}

	// Public principal should get maximum multiplier
	if score.Multiplier != 2.0 {
		t.Errorf("Expected maximum multiplier (2.0) for public principal, got %.2f", score.Multiplier)
	}

	if score.Severity != "CRITICAL" {
		t.Errorf("Expected CRITICAL severity, got %s", score.Severity)
	}
}

func TestCalculateRiskScore_SecretManagerAccess(t *testing.T) {
	finding := HighRiskFinding{
		Type:        "Sensitive Action Access",
		Severity:    "HIGH",
		Description: "Principal can access all secrets",
		Principal: &types.Principal{
			ARN:  "arn:aws:iam::123456789012:role/app-role",
			Type: types.PrincipalTypeRole,
			Name: "app-role",
		},
		Resource: &types.Resource{
			ARN:  "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret",
			Type: types.ResourceTypeSecretsManager,
			Name: "my-secret",
		},
		Action: "secretsmanager:GetSecretValue",
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	score := CalculateRiskScore(finding, context)

	// Secrets Manager should amplify impact
	if score.Impact < 7.0 {
		t.Errorf("Expected high impact for Secrets Manager access, got %.2f", score.Impact)
	}

	// Role should get slight multiplier
	if score.Multiplier < 1.2 {
		t.Errorf("Expected multiplier >= 1.2 for role, got %.2f", score.Multiplier)
	}
}

func TestCalculateRiskScore_LowRiskFinding(t *testing.T) {
	finding := HighRiskFinding{
		Type:        "Direct User Policy Attachment",
		Severity:    "LOW",
		Description: "User has directly attached policy",
		Principal: &types.Principal{
			ARN:  "arn:aws:iam::123456789012:user/developer",
			Type: types.PrincipalTypeUser,
			Name: "developer",
		},
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	score := CalculateRiskScore(finding, context)

	// Low severity finding should have low risk score
	if score.Severity == "CRITICAL" || score.Severity == "HIGH" {
		t.Errorf("Expected LOW or MEDIUM severity, got %s", score.Severity)
	}

	if score.TotalScore > 6.0 {
		t.Errorf("Expected low total score, got %.2f", score.TotalScore)
	}
}

func TestCalculateImpact_ActionTypes(t *testing.T) {
	tests := []struct {
		name          string
		action        string
		expectedMin   float64
		expectedMax   float64
	}{
		{"Wildcard action", "*", 10.0, 10.0},
		{"IAM delete", "iam:DeleteUser", 8.0, 10.0},
		{"S3 delete", "s3:DeleteBucket", 8.0, 10.0},
		{"IAM full", "iam:*", 9.0, 10.0},
		{"KMS decrypt", "kms:Decrypt", 7.0, 10.0},
		{"Secrets get", "secretsmanager:GetSecretValue", 7.0, 10.0},
		{"S3 put", "s3:PutObject", 6.0, 10.0},
		{"S3 get", "s3:GetObject", 4.0, 10.0},
		{"S3 list", "s3:ListBucket", 2.0, 4.0},
		{"EC2 describe", "ec2:DescribeInstances", 2.0, 4.0},
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := HighRiskFinding{
				Action: tt.action,
			}

			impact := calculateImpact(finding, context)

			if impact < tt.expectedMin {
				t.Errorf("Impact %.2f below expected minimum %.2f", impact, tt.expectedMin)
			}

			if impact > tt.expectedMax {
				t.Errorf("Impact %.2f above expected maximum %.2f", impact, tt.expectedMax)
			}
		})
	}
}

func TestCalculateLikelihood_FindingTypes(t *testing.T) {
	tests := []struct {
		name          string
		findingType   string
		severity      string
		expectedMin   float64
	}{
		{"Public Access", "Public Access", "CRITICAL", 9.0},
		{"Wildcard Resource Policy", "Wildcard Resource Policy", "CRITICAL", 9.0},
		{"Cross-Account Access", "Cross-Account Access", "MEDIUM", 7.0},
		{"Admin Access", "Admin Access", "CRITICAL", 7.0},
		{"Service Role Escalation", "Service Role Privilege Escalation", "HIGH", 7.0},
		{"Direct User Policy", "Direct User Policy Attachment", "LOW", 2.0},
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := HighRiskFinding{
				Type:     tt.findingType,
				Severity: tt.severity,
			}

			likelihood := calculateLikelihood(finding, context)

			if likelihood < tt.expectedMin {
				t.Errorf("Likelihood %.2f below expected minimum %.2f", likelihood, tt.expectedMin)
			}

			if likelihood > 10.0 {
				t.Errorf("Likelihood %.2f above maximum 10.0", likelihood)
			}
		})
	}
}

func TestCalculatePrivilegeMultiplier(t *testing.T) {
	tests := []struct {
		name          string
		principal     *types.Principal
		isAdmin       bool
		expected      float64
	}{
		{
			name: "Public principal",
			principal: &types.Principal{
				ARN:  "*",
				Type: types.PrincipalTypePublic,
			},
			isAdmin:  false,
			expected: 2.0,
		},
		{
			name: "Admin user",
			principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
			},
			isAdmin:  true,
			expected: 1.5,
		},
		{
			name: "Regular role",
			principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:role/app-role",
				Type: types.PrincipalTypeRole,
			},
			isAdmin:  false,
			expected: 1.2,
		},
		{
			name: "Regular user",
			principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:user/developer",
				Type: types.PrincipalTypeUser,
			},
			isAdmin:  false,
			expected: 1.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := RiskContext{
				AdminPrincipals: make(map[string]bool),
				TaggedResources: make(map[string]map[string]string),
			}

			if tt.isAdmin {
				context.AdminPrincipals[tt.principal.ARN] = true
			}

			finding := HighRiskFinding{
				Principal: tt.principal,
			}

			multiplier := calculatePrivilegeMultiplier(finding, context)

			if multiplier != tt.expected {
				t.Errorf("Expected multiplier %.2f, got %.2f", tt.expected, multiplier)
			}
		})
	}
}

func TestGenerateRiskSummary(t *testing.T) {
	findings := []HighRiskFinding{
		{
			Type:     "Admin Access",
			Severity: "CRITICAL",
			Action:   "*",
			Principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
			},
		},
		{
			Type:     "Public Access",
			Severity: "CRITICAL",
			Action:   "s3:GetObject",
			Principal: &types.Principal{
				ARN:  "*",
				Type: types.PrincipalTypePublic,
			},
		},
		{
			Type:     "Sensitive Action Access",
			Severity: "HIGH",
			Action:   "iam:*",
			Principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:role/power-role",
				Type: types.PrincipalTypeRole,
			},
		},
		{
			Type:     "Direct User Policy Attachment",
			Severity: "LOW",
			Principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:user/dev",
				Type: types.PrincipalTypeUser,
			},
		},
	}

	context := RiskContext{
		AdminPrincipals: make(map[string]bool),
		TaggedResources: make(map[string]map[string]string),
	}

	summary := GenerateRiskSummary(findings, context)

	if summary.TotalFindings != 4 {
		t.Errorf("Expected 4 total findings, got %d", summary.TotalFindings)
	}

	if summary.CriticalFindings < 1 {
		t.Error("Expected at least 1 critical finding")
	}

	if summary.AverageRiskScore <= 0 {
		t.Error("Average risk score should be greater than 0")
	}

	if len(summary.TopRisks) == 0 {
		t.Error("TopRisks should not be empty")
	}

	// Top risks should be sorted by score descending
	for i := 1; i < len(summary.TopRisks); i++ {
		if summary.TopRisks[i].TotalScore > summary.TopRisks[i-1].TotalScore {
			t.Error("TopRisks should be sorted by TotalScore descending")
		}
	}
}

func TestGetRiskScores_Integration(t *testing.T) {
	g := graph.New()

	// Add admin user
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	// Add public S3 bucket
	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public (Anonymous)",
	}
	g.AddPrincipal(publicPrincipal)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::public-data",
		Type: types.ResourceTypeS3,
		Name: "public-data",
	}
	g.AddResource(bucket)
	g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	scores, err := e.GetRiskScores()

	if err != nil {
		t.Fatalf("GetRiskScores() error = %v", err)
	}

	if len(scores) == 0 {
		t.Error("Expected at least some risk scores")
	}

	// Verify scores are sorted descending
	for i := 1; i < len(scores); i++ {
		if scores[i].TotalScore > scores[i-1].TotalScore {
			t.Error("Risk scores should be sorted by TotalScore descending")
		}
	}

	// Check that all scores have valid components
	for _, score := range scores {
		if score.Impact < 0 || score.Impact > 10 {
			t.Errorf("Impact out of range: %.2f", score.Impact)
		}
		if score.Likelihood < 0 || score.Likelihood > 10 {
			t.Errorf("Likelihood out of range: %.2f", score.Likelihood)
		}
		if score.Multiplier < 1.0 || score.Multiplier > 2.0 {
			t.Errorf("Multiplier out of range: %.2f", score.Multiplier)
		}
		if score.TotalScore < 0 || score.TotalScore > 10 {
			t.Errorf("TotalScore out of range: %.2f", score.TotalScore)
		}
		if score.Severity == "" {
			t.Error("Severity should not be empty")
		}
	}
}

func TestGetRiskSummary_Integration(t *testing.T) {
	g := graph.New()

	// Add various principals with different access patterns
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	s3User := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/s3-power",
		Type: types.PrincipalTypeUser,
		Name: "s3-power",
	}
	g.AddPrincipal(s3User)
	g.AddEdge(s3User.ARN, "s3:*", "*", false)

	e := New(g)
	summary, err := e.GetRiskSummary()

	if err != nil {
		t.Fatalf("GetRiskSummary() error = %v", err)
	}

	if summary.TotalFindings == 0 {
		t.Error("Expected at least some findings")
	}

	// Check distribution makes sense
	total := summary.CriticalFindings + summary.HighFindings + summary.MediumFindings + summary.LowFindings + summary.InfoFindings
	if total != summary.TotalFindings {
		t.Errorf("Severity counts don't match total: %d vs %d", total, summary.TotalFindings)
	}

	if summary.AverageRiskScore < 0 || summary.AverageRiskScore > 10 {
		t.Errorf("Average risk score out of range: %.2f", summary.AverageRiskScore)
	}

	if len(summary.TopRisks) == 0 {
		t.Error("TopRisks should not be empty when findings exist")
	}
}

func TestMapScoreToSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{10.0, "CRITICAL"},
		{9.5, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.0, "HIGH"},
		{7.0, "HIGH"},
		{6.0, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.0, "LOW"},
		{1.0, "LOW"},
		{0.5, "INFO"},
		{0.0, "INFO"},
	}

	for _, tt := range tests {
		result := mapScoreToSeverity(tt.score)
		if result != tt.expected {
			t.Errorf("mapScoreToSeverity(%.1f) = %s, want %s", tt.score, result, tt.expected)
		}
	}
}
