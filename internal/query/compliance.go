package query

import (
	"fmt"
	"sort"
)

// ComplianceFramework represents a compliance standard
type ComplianceFramework string

const (
	FrameworkCIS     ComplianceFramework = "CIS AWS Foundations Benchmark"
	FrameworkPCIDSS  ComplianceFramework = "PCI-DSS v3.2.1"
	FrameworkSOC2    ComplianceFramework = "SOC 2"
	FrameworkAll     ComplianceFramework = "All Frameworks"
)

// ComplianceControl represents a specific control in a framework
type ComplianceControl struct {
	ID          string              // Control ID (e.g., "CIS-1.16", "PCI-7.1.2")
	Framework   ComplianceFramework // Which framework this belongs to
	Title       string              // Control title
	Description string              // Control description
	Severity    string              // CRITICAL/HIGH/MEDIUM/LOW
	Rationale   string              // Why this control matters
}

// ComplianceFinding represents a finding mapped to compliance controls
type ComplianceFinding struct {
	Control     ComplianceControl
	Status      string // PASS/FAIL
	Finding     *HighRiskFinding // Associated security finding (if FAIL)
	Evidence    string // Evidence for the finding
	Remediation string // How to fix
}

// ComplianceReport aggregates findings by framework
type ComplianceReport struct {
	Framework      ComplianceFramework
	TotalControls  int
	PassedControls int
	FailedControls int
	Findings       []ComplianceFinding
	ComplianceRate float64 // Percentage of controls passed
}

// Compliance control definitions
var CISControls = []ComplianceControl{
	{
		ID:          "CIS-1.16",
		Framework:   FrameworkCIS,
		Title:       "Ensure IAM policies are attached only to groups or roles",
		Description: "IAM policies should be attached to groups or roles instead of users",
		Severity:    "LOW",
		Rationale:   "Assigning privileges at the group or role level reduces the complexity of access management",
	},
	{
		ID:          "CIS-1.12",
		Framework:   FrameworkCIS,
		Title:       "Ensure credentials unused for 90 days or greater are disabled",
		Description: "Credentials should be disabled if not used within 90 days",
		Severity:    "MEDIUM",
		Rationale:   "Disabling unused credentials reduces the attack surface",
	},
	{
		ID:          "CIS-1.13",
		Framework:   FrameworkCIS,
		Title:       "Ensure there is only one active access key available for any single IAM user",
		Description: "IAM users should have only one active access key",
		Severity:    "MEDIUM",
		Rationale:   "Multiple access keys increase the risk of credential compromise",
	},
	{
		ID:          "CIS-1.14",
		Framework:   FrameworkCIS,
		Title:       "Ensure access keys are rotated every 90 days or less",
		Description: "Access keys should be rotated regularly",
		Severity:    "MEDIUM",
		Rationale:   "Regular rotation reduces the impact of compromised credentials",
	},
	{
		ID:          "CIS-1.20",
		Framework:   FrameworkCIS,
		Title:       "Ensure a support role has been created to manage incidents with AWS Support",
		Description: "Support role enables management of AWS Support cases",
		Severity:    "LOW",
		Rationale:   "Ensures proper support access during security incidents",
	},
	{
		ID:          "CIS-1.22",
		Framework:   FrameworkCIS,
		Title:       "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created",
		Description: "Avoid creating policies with wildcard permissions",
		Severity:    "CRITICAL",
		Rationale:   "Wildcard permissions grant unrestricted access to all AWS services",
	},
	{
		ID:          "CIS-2.1.1",
		Framework:   FrameworkCIS,
		Title:       "Ensure S3 Bucket Policy allows HTTPS only",
		Description: "S3 buckets should deny requests that are not using HTTPS",
		Severity:    "HIGH",
		Rationale:   "Enforcing HTTPS prevents data interception in transit",
	},
	{
		ID:          "CIS-2.1.5",
		Framework:   FrameworkCIS,
		Title:       "Ensure that S3 Buckets are configured with 'Block public access'",
		Description: "S3 buckets should block public access by default",
		Severity:    "CRITICAL",
		Rationale:   "Public access can lead to data breaches",
	},
}

var PCIDSSControls = []ComplianceControl{
	{
		ID:          "PCI-7.1.1",
		Framework:   FrameworkPCIDSS,
		Title:       "Limit access to system components and cardholder data to only those with job need",
		Description: "Access should be based on job function and least privilege",
		Severity:    "HIGH",
		Rationale:   "Reduces risk of unauthorized access to cardholder data",
	},
	{
		ID:          "PCI-7.1.2",
		Framework:   FrameworkPCIDSS,
		Title:       "Restrict access to privileged user IDs to least privileges necessary",
		Description: "Privileged accounts should have minimum necessary permissions",
		Severity:    "CRITICAL",
		Rationale:   "Overprivileged accounts are high-value targets",
	},
	{
		ID:          "PCI-7.2.1",
		Framework:   FrameworkPCIDSS,
		Title:       "Coverage of all system components with access control systems",
		Description: "All components must have access controls defined",
		Severity:    "HIGH",
		Rationale:   "Ensures no components lack security controls",
	},
	{
		ID:          "PCI-7.2.2",
		Framework:   FrameworkPCIDSS,
		Title:       "Assignment of privileges based on job classification and function",
		Description: "Privileges assigned based on roles, not individuals",
		Severity:    "MEDIUM",
		Rationale:   "Role-based access control reduces management complexity",
	},
	{
		ID:          "PCI-8.1.4",
		Framework:   FrameworkPCIDSS,
		Title:       "Remove/disable inactive user accounts within 90 days",
		Description: "Inactive accounts must be promptly disabled",
		Severity:    "HIGH",
		Rationale:   "Dormant accounts are security risks",
	},
	{
		ID:          "PCI-8.2.3",
		Framework:   FrameworkPCIDSS,
		Title:       "Passwords must meet minimum strength requirements",
		Description: "Strong authentication credentials required",
		Severity:    "HIGH",
		Rationale:   "Weak credentials enable unauthorized access",
	},
	{
		ID:          "PCI-8.3.1",
		Framework:   FrameworkPCIDSS,
		Title:       "Incorporate multi-factor authentication for all non-console administrative access",
		Description: "MFA required for admin access",
		Severity:    "CRITICAL",
		Rationale:   "MFA prevents credential-only attacks",
	},
}

var SOC2Controls = []ComplianceControl{
	{
		ID:          "CC6.1",
		Framework:   FrameworkSOC2,
		Title:       "Logical and Physical Access Controls",
		Description: "Organization restricts logical and physical access",
		Severity:    "HIGH",
		Rationale:   "Access controls protect system integrity and confidentiality",
	},
	{
		ID:          "CC6.2",
		Framework:   FrameworkSOC2,
		Title:       "Prior to Issuing System Credentials",
		Description: "Authorize and register new internal/external users",
		Severity:    "MEDIUM",
		Rationale:   "Prevents unauthorized credential issuance",
	},
	{
		ID:          "CC6.3",
		Framework:   FrameworkSOC2,
		Title:       "System Credentials Removed When Access Is No Longer Required",
		Description: "Credentials removed promptly when access ends",
		Severity:    "MEDIUM",
		Rationale:   "Reduces credential sprawl and orphaned accounts",
	},
	{
		ID:          "CC6.6",
		Framework:   FrameworkSOC2,
		Title:       "Logical Access Security Measures",
		Description: "Security measures protect against threats to system security",
		Severity:    "HIGH",
		Rationale:   "Defense-in-depth prevents security breaches",
	},
	{
		ID:          "CC6.7",
		Framework:   FrameworkSOC2,
		Title:       "Access Restrictions Transmission, Movement, and Removal of Information",
		Description: "Restrict transmission and movement of sensitive information",
		Severity:    "HIGH",
		Rationale:   "Prevents data exfiltration",
	},
}

// MapFindingsToCompliance maps security findings to compliance controls
func MapFindingsToCompliance(findings []HighRiskFinding, framework ComplianceFramework) []ComplianceFinding {
	var complianceFindings []ComplianceFinding

	// Get controls for the framework
	var controls []ComplianceControl
	switch framework {
	case FrameworkCIS:
		controls = CISControls
	case FrameworkPCIDSS:
		controls = PCIDSSControls
	case FrameworkSOC2:
		controls = SOC2Controls
	case FrameworkAll:
		controls = append(append(CISControls, PCIDSSControls...), SOC2Controls...)
	}

	// Map each control to findings
	for _, control := range controls {
		finding := mapControlToFinding(control, findings)
		complianceFindings = append(complianceFindings, finding)
	}

	return complianceFindings
}

// mapControlToFinding maps a specific control to a finding
func mapControlToFinding(control ComplianceControl, findings []HighRiskFinding) ComplianceFinding {
	cf := ComplianceFinding{
		Control: control,
		Status:  "PASS", // Default to PASS
	}

	// Map control to finding patterns
	switch control.ID {
	case "CIS-1.16":
		// Check for direct user policy attachments
		for _, f := range findings {
			if f.Type == "Direct User Policy Attachment" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Attach policies to IAM groups instead of directly to users. Create groups for common roles and add users to groups."
				break
			}
		}

	case "CIS-1.22", "PCI-7.1.2":
		// Check for admin access
		for _, f := range findings {
			if f.Type == "Admin Access" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Restrict wildcard permissions. Create specific policies with least-privilege access. Use permission boundaries."
				break
			}
		}

	case "CIS-2.1.5", "CC6.1":
		// Check for public S3 access
		for _, f := range findings {
			if f.Type == "Public Access" && f.Resource != nil {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Enable S3 Block Public Access at account/bucket level. Review bucket policies and ACLs. Use CloudFront for public content."
				break
			}
		}

	case "CIS-2.1.1":
		// Check for HTTPS-only S3 access (would need additional data)
		cf.Status = "PASS"
		cf.Evidence = "Unable to verify - requires bucket policy inspection for aws:SecureTransport condition"

	case "PCI-7.1.1", "PCI-7.2.1", "CC6.6":
		// Check for overly permissive S3 or Lambda access
		for _, f := range findings {
			if f.Type == "Overly Permissive S3 Access" || f.Type == "Overly Permissive Lambda Role" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Apply least-privilege principle. Scope permissions to specific resources. Use resource-based policies."
				break
			}
		}

	case "PCI-7.2.2", "CC6.2":
		// Check for role-based access (direct user policies violate this)
		for _, f := range findings {
			if f.Type == "Direct User Policy Attachment" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Implement role-based access control using IAM groups. Define job functions and map to groups."
				break
			}
		}

	case "PCI-8.3.1":
		// Check for missing MFA
		for _, f := range findings {
			if f.Type == "Missing MFA for Privileged User" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Require MFA for all privileged users. Add aws:MultiFactorAuthPresent condition to policies. Enable MFA devices."
				break
			}
		}

	case "CC6.7":
		// Check for broad network access
		for _, f := range findings {
			if f.Type == "Broad Network Access" {
				cf.Status = "FAIL"
				cf.Finding = &f
				cf.Evidence = f.Description
				cf.Remediation = "Add IP address restrictions to resource policies. Use aws:SourceIp condition. Implement VPC endpoints."
				break
			}
		}

	default:
		// Controls without direct mapping
		cf.Status = "PASS"
		cf.Evidence = "No findings detected for this control"
	}

	return cf
}

// GenerateComplianceReport creates a compliance report for a framework
func (e *Engine) GenerateComplianceReport(framework ComplianceFramework) (ComplianceReport, error) {
	// Get all findings
	findings, err := e.FindHighRiskAccess()
	if err != nil {
		return ComplianceReport{}, fmt.Errorf("failed to find high-risk access: %w", err)
	}

	// Map to compliance
	complianceFindings := MapFindingsToCompliance(findings, framework)

	// Count passed/failed
	report := ComplianceReport{
		Framework:     framework,
		TotalControls: len(complianceFindings),
		Findings:      complianceFindings,
	}

	for _, finding := range complianceFindings {
		if finding.Status == "PASS" {
			report.PassedControls++
		} else {
			report.FailedControls++
		}
	}

	// Calculate compliance rate
	if report.TotalControls > 0 {
		report.ComplianceRate = float64(report.PassedControls) / float64(report.TotalControls) * 100.0
	}

	return report, nil
}

// GetAllComplianceReports generates reports for all frameworks
func (e *Engine) GetAllComplianceReports() (map[ComplianceFramework]ComplianceReport, error) {
	reports := make(map[ComplianceFramework]ComplianceReport)

	frameworks := []ComplianceFramework{FrameworkCIS, FrameworkPCIDSS, FrameworkSOC2}

	for _, framework := range frameworks {
		report, err := e.GenerateComplianceReport(framework)
		if err != nil {
			return nil, err
		}
		reports[framework] = report
	}

	return reports, nil
}

// GetFailedControls returns only the failed controls for a framework
func (e *Engine) GetFailedControls(framework ComplianceFramework) ([]ComplianceFinding, error) {
	report, err := e.GenerateComplianceReport(framework)
	if err != nil {
		return nil, err
	}

	var failed []ComplianceFinding
	for _, finding := range report.Findings {
		if finding.Status == "FAIL" {
			failed = append(failed, finding)
		}
	}

	// Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
	sort.Slice(failed, func(i, j int) bool {
		severityOrder := map[string]int{
			"CRITICAL": 4,
			"HIGH":     3,
			"MEDIUM":   2,
			"LOW":      1,
		}
		return severityOrder[failed[i].Control.Severity] > severityOrder[failed[j].Control.Severity]
	})

	return failed, nil
}
