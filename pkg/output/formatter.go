package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pfrederiksen/aws-access-map/internal/query"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// PrintWhoCan outputs who-can results in the specified format
func PrintWhoCan(format string, resource, action string, principals []*types.Principal) error {
	if format == "json" {
		return printWhoCanJSON(resource, action, principals)
	}
	return printWhoCanText(resource, action, principals)
}

// PrintPaths outputs path results in the specified format
func PrintPaths(format string, from, to, action string, paths []*types.AccessPath) error {
	if format == "json" {
		return printPathsJSON(from, to, action, paths)
	}
	return printPathsText(from, to, action, paths)
}

// PrintReport outputs report results in the specified format
func PrintReport(format string, accountID string, findings []query.HighRiskFinding) error {
	if format == "json" {
		return printReportJSON(accountID, findings)
	}
	return printReportText(accountID, findings)
}

// PrintCollect outputs collection summary in the specified format
func PrintCollect(format string, result *types.CollectionResult, outputFile string) error {
	if format == "json" {
		return printCollectJSON(result)
	}
	return printCollectText(result, outputFile)
}

// printWhoCanJSON outputs who-can results as JSON
func printWhoCanJSON(resource, action string, principals []*types.Principal) error {
	output := WhoCanOutput{
		Resource:   resource,
		Action:     action,
		Principals: make([]PrincipalOutput, len(principals)),
	}

	for i, p := range principals {
		output.Principals[i] = PrincipalOutput{
			ARN:       p.ARN,
			Type:      string(p.Type),
			Name:      p.Name,
			AccountID: p.AccountID,
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// printWhoCanText outputs who-can results as human-readable text
func printWhoCanText(resource, action string, principals []*types.Principal) error {
	if len(principals) == 0 {
		fmt.Println("No principals found with access to this resource.")
		return nil
	}

	fmt.Printf("Found %d principal(s) with access:\n\n", len(principals))
	for _, p := range principals {
		fmt.Printf("  %s (%s)\n", p.Name, p.Type)
		fmt.Printf("    ARN: %s\n\n", p.ARN)
	}

	return nil
}

// printPathsJSON outputs path results as JSON
func printPathsJSON(from, to, action string, paths []*types.AccessPath) error {
	output := PathsOutput{
		From:   from,
		To:     to,
		Action: action,
		Paths:  make([]PathOutput, len(paths)),
	}

	for i, path := range paths {
		pathOut := PathOutput{
			Hops:       make([]HopOutput, len(path.Hops)),
			Conditions: path.Conditions,
		}

		for j, hop := range path.Hops {
			hopOut := HopOutput{
				From: PrincipalOutput{
					ARN:       hop.From.ARN,
					Type:      string(hop.From.Type),
					Name:      hop.From.Name,
					AccountID: hop.From.AccountID,
				},
				Action:     hop.Action,
				PolicyType: string(hop.PolicyType),
				PolicyName: hop.PolicyName,
				Conditions: hop.Conditions,
			}

			// Handle To field (can be Principal or Resource)
			switch v := hop.To.(type) {
			case *types.Principal:
				hopOut.To = PrincipalOutput{
					ARN:       v.ARN,
					Type:      string(v.Type),
					Name:      v.Name,
					AccountID: v.AccountID,
				}
			case *types.Resource:
				hopOut.To = ResourceOutput{
					ARN:       v.ARN,
					Type:      string(v.Type),
					Name:      v.Name,
					Region:    v.Region,
					AccountID: v.AccountID,
				}
			}

			pathOut.Hops[j] = hopOut
		}

		output.Paths[i] = pathOut
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// printPathsText outputs path results as human-readable text
func printPathsText(from, to, action string, paths []*types.AccessPath) error {
	if len(paths) == 0 {
		fmt.Println("No access paths found.")
		return nil
	}

	fmt.Printf("Found %d path(s):\n\n", len(paths))
	for i, path := range paths {
		fmt.Printf("Path %d:\n", i+1)
		for j, hop := range path.Hops {
			toStr := ""
			switch v := hop.To.(type) {
			case *types.Principal:
				toStr = v.Name
			case *types.Resource:
				toStr = v.Name
			default:
				toStr = fmt.Sprintf("%v", v)
			}

			// Show hop details
			fmt.Printf("  %d. %s -[%s]-> %s", j+1, hop.From.Name, hop.Action, toStr)

			// Show policy name if present
			if hop.PolicyName != "" {
				fmt.Printf(" (via %s)", hop.PolicyName)
			}
			fmt.Println()

			// Show conditions for this hop if present
			if len(hop.Conditions) > 0 {
				fmt.Println("     Conditions:")
				for _, cond := range hop.Conditions {
					fmt.Printf("       - %s\n", cond)
				}
			}
		}

		// Show path-level conditions if present (deprecated, but keep for backward compatibility)
		if len(path.Conditions) > 0 {
			fmt.Println("  Path Conditions:")
			for _, cond := range path.Conditions {
				fmt.Printf("    - %s\n", cond)
			}
		}
		fmt.Println()
	}

	return nil
}

// printReportJSON outputs report results as JSON
func printReportJSON(accountID string, findings []query.HighRiskFinding) error {
	output := ReportOutput{
		AccountID:   accountID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:    make([]FindingOutput, len(findings)),
	}

	for i, finding := range findings {
		findingOut := FindingOutput{
			Type:        finding.Type,
			Severity:    finding.Severity,
			Description: finding.Description,
			Action:      finding.Action,
		}

		if finding.Principal != nil {
			findingOut.Principal = &PrincipalOutput{
				ARN:       finding.Principal.ARN,
				Type:      string(finding.Principal.Type),
				Name:      finding.Principal.Name,
				AccountID: finding.Principal.AccountID,
			}
		}

		if finding.Resource != nil {
			findingOut.Resource = &ResourceOutput{
				ARN:       finding.Resource.ARN,
				Type:      string(finding.Resource.Type),
				Name:      finding.Resource.Name,
				Region:    finding.Resource.Region,
				AccountID: finding.Resource.AccountID,
			}
		}

		output.Findings[i] = findingOut
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// printReportText outputs report results as human-readable text
func printReportText(accountID string, findings []query.HighRiskFinding) error {
	if len(findings) == 0 {
		fmt.Println("No high-risk findings detected.")
		return nil
	}

	fmt.Printf("Found %d high-risk finding(s):\n\n", len(findings))
	for i, finding := range findings {
		fmt.Printf("%d. [%s] %s\n", i+1, finding.Severity, finding.Type)
		fmt.Printf("   %s\n\n", finding.Description)
	}

	return nil
}

// printCollectJSON outputs collection summary as JSON
func printCollectJSON(result *types.CollectionResult) error {
	output := CollectOutput{
		AccountID:      result.AccountID,
		Regions:        result.Regions,
		CollectedAt:    result.CollectedAt,
		PrincipalCount: len(result.Principals),
		ResourceCount:  len(result.Resources),
		SCPCount:       len(result.SCPs),
		Principals:     make([]PrincipalOutput, len(result.Principals)),
		Resources:      make([]ResourceOutput, len(result.Resources)),
		SCPs:           make([]SCPOutput, len(result.SCPs)),
	}

	for i, p := range result.Principals {
		output.Principals[i] = PrincipalOutput{
			ARN:       p.ARN,
			Type:      string(p.Type),
			Name:      p.Name,
			AccountID: p.AccountID,
		}
	}

	for i, r := range result.Resources {
		output.Resources[i] = ResourceOutput{
			ARN:       r.ARN,
			Type:      string(r.Type),
			Name:      r.Name,
			Region:    r.Region,
			AccountID: r.AccountID,
		}
	}

	for i, scp := range result.SCPs {
		output.SCPs[i] = SCPOutput{
			ID: scp.ID,
			// SCPs don't have Name field in PolicyDocument, using ID as identifier
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// printCollectText outputs collection summary as human-readable text
func printCollectText(result *types.CollectionResult, outputFile string) error {
	fmt.Printf("Collected %d principals\n", len(result.Principals))
	fmt.Printf("Collected %d resources\n", len(result.Resources))

	if len(result.SCPs) > 0 {
		fmt.Printf("Collected %d Service Control Policies (SCPs)\n", len(result.SCPs))
	} else {
		fmt.Println("No SCPs collected (use --include-scps flag to collect organization policies)")
	}

	fmt.Printf("Data saved to %s\n", outputFile)
	return nil
}
