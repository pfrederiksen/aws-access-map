package query

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestMapFindingsToCompliance_CIS(t *testing.T) {
	findings := []HighRiskFinding{
		{
			Type:     "Direct User Policy Attachment",
			Severity: "LOW",
			Principal: &types.Principal{
				Name: "test-user",
			},
		},
		{
			Type:     "Admin Access",
			Severity: "CRITICAL",
			Principal: &types.Principal{
				Name: "admin-user",
			},
		},
	}

	complianceFindings := MapFindingsToCompliance(findings, FrameworkCIS)

	if len(complianceFindings) == 0 {
		t.Fatal("Expected compliance findings for CIS framework")
	}

	// Check that CIS-1.16 fails (direct user policy)
	foundCIS116 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "CIS-1.16" {
			foundCIS116 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected CIS-1.16 to FAIL, got %s", cf.Status)
			}
			if cf.Remediation == "" {
				t.Error("Expected remediation guidance for CIS-1.16")
			}
		}
	}

	if !foundCIS116 {
		t.Error("Expected to find CIS-1.16 control")
	}

	// Check that CIS-1.22 fails (admin access)
	foundCIS122 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "CIS-1.22" {
			foundCIS122 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected CIS-1.22 to FAIL, got %s", cf.Status)
			}
		}
	}

	if !foundCIS122 {
		t.Error("Expected to find CIS-1.22 control")
	}
}

func TestMapFindingsToCompliance_PCIDSS(t *testing.T) {
	findings := []HighRiskFinding{
		{
			Type:     "Missing MFA for Privileged User",
			Severity: "MEDIUM",
			Principal: &types.Principal{
				Name: "privileged-user",
			},
		},
		{
			Type:     "Admin Access",
			Severity: "CRITICAL",
			Action:   "*",
		},
	}

	complianceFindings := MapFindingsToCompliance(findings, FrameworkPCIDSS)

	if len(complianceFindings) == 0 {
		t.Fatal("Expected compliance findings for PCI-DSS framework")
	}

	// Check that PCI-8.3.1 fails (missing MFA)
	foundPCI831 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "PCI-8.3.1" {
			foundPCI831 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected PCI-8.3.1 to FAIL, got %s", cf.Status)
			}
			if cf.Finding == nil {
				t.Error("Expected finding reference for PCI-8.3.1")
			}
		}
	}

	if !foundPCI831 {
		t.Error("Expected to find PCI-8.3.1 control")
	}

	// Check that PCI-7.1.2 fails (admin access)
	foundPCI712 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "PCI-7.1.2" {
			foundPCI712 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected PCI-7.1.2 to FAIL, got %s", cf.Status)
			}
		}
	}

	if !foundPCI712 {
		t.Error("Expected to find PCI-7.1.2 control")
	}
}

func TestMapFindingsToCompliance_SOC2(t *testing.T) {
	findings := []HighRiskFinding{
		{
			Type:     "Public Access",
			Severity: "CRITICAL",
			Resource: &types.Resource{
				Name: "public-bucket",
				Type: types.ResourceTypeS3,
			},
		},
		{
			Type:     "Broad Network Access",
			Severity: "MEDIUM",
			Resource: &types.Resource{
				Name: "open-api",
			},
		},
	}

	complianceFindings := MapFindingsToCompliance(findings, FrameworkSOC2)

	if len(complianceFindings) == 0 {
		t.Fatal("Expected compliance findings for SOC2 framework")
	}

	// Check that CC6.1 fails (public access)
	foundCC61 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "CC6.1" {
			foundCC61 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected CC6.1 to FAIL, got %s", cf.Status)
			}
		}
	}

	if !foundCC61 {
		t.Error("Expected to find CC6.1 control")
	}

	// Check that CC6.7 fails (broad network access)
	foundCC67 := false
	for _, cf := range complianceFindings {
		if cf.Control.ID == "CC6.7" {
			foundCC67 = true
			if cf.Status != "FAIL" {
				t.Errorf("Expected CC6.7 to FAIL, got %s", cf.Status)
			}
		}
	}

	if !foundCC67 {
		t.Error("Expected to find CC6.7 control")
	}
}

func TestGenerateComplianceReport_CIS(t *testing.T) {
	g := graph.New()

	// Add user with direct policy
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/test-user",
		Type: types.PrincipalTypeUser,
		Name: "test-user",
		Policies: []types.PolicyDocument{
			{
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:GetObject",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(user)

	e := New(g)
	report, err := e.GenerateComplianceReport(FrameworkCIS)

	if err != nil {
		t.Fatalf("GenerateComplianceReport() error = %v", err)
	}

	if report.Framework != FrameworkCIS {
		t.Errorf("Expected framework %s, got %s", FrameworkCIS, report.Framework)
	}

	if report.TotalControls == 0 {
		t.Error("Expected non-zero total controls")
	}

	if report.ComplianceRate < 0 || report.ComplianceRate > 100 {
		t.Errorf("Compliance rate out of range: %.2f", report.ComplianceRate)
	}

	// Should have at least one failure (CIS-1.16)
	if report.FailedControls == 0 {
		t.Error("Expected at least one failed control")
	}

	// Passed + Failed should equal Total
	if report.PassedControls+report.FailedControls != report.TotalControls {
		t.Errorf("Control counts don't match: %d passed + %d failed != %d total",
			report.PassedControls, report.FailedControls, report.TotalControls)
	}
}

func TestGenerateComplianceReport_PCIDSS(t *testing.T) {
	g := graph.New()

	// Add admin user
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	e := New(g)
	report, err := e.GenerateComplianceReport(FrameworkPCIDSS)

	if err != nil {
		t.Fatalf("GenerateComplianceReport() error = %v", err)
	}

	if report.Framework != FrameworkPCIDSS {
		t.Errorf("Expected framework %s, got %s", FrameworkPCIDSS, report.Framework)
	}

	if report.TotalControls == 0 {
		t.Error("Expected non-zero total controls")
	}

	// Should have failures for admin access
	if report.FailedControls == 0 {
		t.Error("Expected at least one failed control for admin access")
	}

	// Check that findings have evidence and remediation
	for _, finding := range report.Findings {
		if finding.Status == "FAIL" {
			if finding.Evidence == "" {
				t.Errorf("Control %s lacks evidence", finding.Control.ID)
			}
			if finding.Remediation == "" {
				t.Errorf("Control %s lacks remediation", finding.Control.ID)
			}
		}
	}
}

func TestGenerateComplianceReport_SOC2(t *testing.T) {
	g := graph.New()

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
	report, err := e.GenerateComplianceReport(FrameworkSOC2)

	if err != nil {
		t.Fatalf("GenerateComplianceReport() error = %v", err)
	}

	if report.Framework != FrameworkSOC2 {
		t.Errorf("Expected framework %s, got %s", FrameworkSOC2, report.Framework)
	}

	// Should have failures for public access
	if report.FailedControls == 0 {
		t.Error("Expected at least one failed control for public access")
	}
}

func TestGetAllComplianceReports(t *testing.T) {
	g := graph.New()

	// Add various security issues
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
		Policies: []types.PolicyDocument{
			{
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	e := New(g)
	reports, err := e.GetAllComplianceReports()

	if err != nil {
		t.Fatalf("GetAllComplianceReports() error = %v", err)
	}

	expectedFrameworks := []ComplianceFramework{FrameworkCIS, FrameworkPCIDSS, FrameworkSOC2}

	for _, framework := range expectedFrameworks {
		report, exists := reports[framework]
		if !exists {
			t.Errorf("Missing report for framework %s", framework)
			continue
		}

		if report.TotalControls == 0 {
			t.Errorf("Framework %s has zero controls", framework)
		}

		if report.Framework != framework {
			t.Errorf("Framework mismatch: expected %s, got %s", framework, report.Framework)
		}
	}
}

func TestGetFailedControls(t *testing.T) {
	g := graph.New()

	// Add multiple security issues
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user-with-policies",
		Type: types.PrincipalTypeUser,
		Name: "user-with-policies",
		Policies: []types.PolicyDocument{
			{
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
	}
	g.AddPrincipal(user)
	g.AddEdge(user.ARN, "*", "*", false)

	e := New(g)
	failed, err := e.GetFailedControls(FrameworkCIS)

	if err != nil {
		t.Fatalf("GetFailedControls() error = %v", err)
	}

	if len(failed) == 0 {
		t.Error("Expected at least one failed control")
	}

	// Verify all returned controls are actually failed
	for _, control := range failed {
		if control.Status != "FAIL" {
			t.Errorf("Expected only FAIL status, got %s for control %s", control.Status, control.Control.ID)
		}
	}

	// Verify controls are sorted by severity
	severityOrder := map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}

	for i := 1; i < len(failed); i++ {
		prevSeverity := severityOrder[failed[i-1].Control.Severity]
		currSeverity := severityOrder[failed[i].Control.Severity]

		if currSeverity > prevSeverity {
			t.Errorf("Failed controls not sorted by severity: %s (order %d) before %s (order %d)",
				failed[i-1].Control.Severity, prevSeverity,
				failed[i].Control.Severity, currSeverity)
		}
	}
}

func TestComplianceRate_Calculation(t *testing.T) {
	g := graph.New()

	// Add a compliant setup (no violations)
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/compliant-user",
		Type: types.PrincipalTypeUser,
		Name: "compliant-user",
		// No policies attached (compliant with CIS-1.16)
	}
	g.AddPrincipal(user)

	e := New(g)
	report, err := e.GenerateComplianceReport(FrameworkCIS)

	if err != nil {
		t.Fatalf("GenerateComplianceReport() error = %v", err)
	}

	// With no violations, compliance rate should be high
	if report.ComplianceRate < 50.0 {
		t.Errorf("Expected high compliance rate for compliant setup, got %.2f%%", report.ComplianceRate)
	}

	// Now add violations
	g2 := graph.New()
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
		Policies: []types.PolicyDocument{
			{
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
	}
	g2.AddPrincipal(admin)
	g2.AddEdge(admin.ARN, "*", "*", false)

	e2 := New(g2)
	report2, err := e2.GenerateComplianceReport(FrameworkCIS)

	if err != nil {
		t.Fatalf("GenerateComplianceReport() error = %v", err)
	}

	// With violations, compliance rate should be lower
	if report2.ComplianceRate >= report.ComplianceRate {
		t.Errorf("Expected lower compliance with violations: %.2f%% vs %.2f%%",
			report2.ComplianceRate, report.ComplianceRate)
	}
}

func TestControlDefinitions(t *testing.T) {
	// Verify CIS controls
	if len(CISControls) == 0 {
		t.Error("CIS controls should not be empty")
	}

	for _, control := range CISControls {
		if control.ID == "" {
			t.Error("CIS control missing ID")
		}
		if control.Framework != FrameworkCIS {
			t.Errorf("CIS control %s has wrong framework: %s", control.ID, control.Framework)
		}
		if control.Title == "" {
			t.Errorf("CIS control %s missing title", control.ID)
		}
		if control.Description == "" {
			t.Errorf("CIS control %s missing description", control.ID)
		}
		if control.Severity == "" {
			t.Errorf("CIS control %s missing severity", control.ID)
		}
	}

	// Verify PCI-DSS controls
	if len(PCIDSSControls) == 0 {
		t.Error("PCI-DSS controls should not be empty")
	}

	for _, control := range PCIDSSControls {
		if control.Framework != FrameworkPCIDSS {
			t.Errorf("PCI-DSS control %s has wrong framework: %s", control.ID, control.Framework)
		}
	}

	// Verify SOC2 controls
	if len(SOC2Controls) == 0 {
		t.Error("SOC2 controls should not be empty")
	}

	for _, control := range SOC2Controls {
		if control.Framework != FrameworkSOC2 {
			t.Errorf("SOC2 control %s has wrong framework: %s", control.ID, control.Framework)
		}
	}
}
