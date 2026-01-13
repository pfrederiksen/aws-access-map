package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/internal/query"
	"github.com/pfrederiksen/aws-access-map/internal/simulation"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// simulateCmd returns the simulate command group
func simulateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate access queries without AWS credentials",
		Long: `Load policies from local files and run access queries. Useful for testing
policy changes before deployment, CI/CD integration, and local development.`,
		Example: `  # Query local policies
  aws-access-map simulate who-can "arn:aws:s3:::bucket/*" --action s3:GetObject --data policies.json

  # Compare before and after
  aws-access-map simulate diff --before current.json --after proposed.json --action "*"

  # Test a policy change
  aws-access-map simulate test --data current.json --add-policy new-policy.json --principal arn:aws:iam::123:role/MyRole

  # Validate for security issues
  aws-access-map simulate validate --data policies.json`,
	}

	cmd.AddCommand(simulateWhoCanCmd())
	cmd.AddCommand(simulateDiffCmd())
	cmd.AddCommand(simulateTestCmd())
	cmd.AddCommand(simulateValidateCmd())

	return cmd
}

// simulateWhoCanCmd implements the "simulate who-can" subcommand
func simulateWhoCanCmd() *cobra.Command {
	var dataFile string
	var action string

	cmd := &cobra.Command{
		Use:   "who-can <resource>",
		Short: "Find principals that can access a resource (using local data)",
		Long: `Query local policy data to find which principals can access a resource.
This command does not connect to AWS and works entirely with local files.`,
		Example: `  # Check who can read from S3
  aws-access-map simulate who-can "arn:aws:s3:::bucket/*" --action s3:GetObject --data policies.json

  # Check admin access
  aws-access-map simulate who-can "*" --action "*" --data policies.json

  # Check Lambda invocation
  aws-access-map simulate who-can "arn:aws:lambda:us-east-1:123:function:fn" --action lambda:InvokeFunction --data policies.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resourceARN := args[0]

			// Validate inputs
			if dataFile == "" {
				return fmt.Errorf("--data is required")
			}
			if action == "" {
				return fmt.Errorf("--action is required")
			}

			// Load data from file
			result, err := simulation.LoadFromFile(dataFile)
			if err != nil {
				return fmt.Errorf("failed to load data: %w", err)
			}

			// Build graph
			g, err := graph.Build(result)
			if err != nil {
				return fmt.Errorf("failed to build graph: %w", err)
			}

			// Create query engine with evaluation context
			evalCtx := buildEvaluationContext()
			q := query.New(g).WithContext(evalCtx)

			// Query for principals
			principals, err := q.WhoCan(resourceARN, action)
			if err != nil {
				return fmt.Errorf("failed to query: %w", err)
			}

			// Output results
			if format == "json" {
				data, err := json.MarshalIndent(principals, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Text output
			if len(principals) == 0 {
				fmt.Printf("No principals can perform %s on %s\n", action, resourceARN)
				return nil
			}

			fmt.Printf("Principals that can perform %s on %s:\n\n", action, resourceARN)
			for _, principal := range principals {
				fmt.Printf("  %s (%s)\n", principal.ARN, principal.Type)
			}
			fmt.Printf("\nTotal: %d principal(s)\n", len(principals))

			return nil
		},
	}

	cmd.Flags().StringVar(&dataFile, "data", "", "Local policy data file (JSON)")
	cmd.Flags().StringVar(&action, "action", "", "Action to check (e.g., s3:GetObject, *)")

	_ = cmd.MarkFlagRequired("data")
	_ = cmd.MarkFlagRequired("action")

	return cmd
}

// simulateDiffCmd implements the "simulate diff" subcommand
func simulateDiffCmd() *cobra.Command {
	var beforeFile, afterFile, resourceARN, action string

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare access between two policy sets",
		Long: `Compare who can access a resource between two policy sets.
Shows which principals gained access, lost access, or kept the same access.`,
		Example: `  # Compare before and after policy changes
  aws-access-map simulate diff --before current.json --after proposed.json --action "*"

  # Compare for specific action
  aws-access-map simulate diff \
    --before current.json \
    --after proposed.json \
    --resource "arn:aws:s3:::bucket/*" \
    --action s3:DeleteObject`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate inputs
			if beforeFile == "" {
				return fmt.Errorf("--before is required")
			}
			if afterFile == "" {
				return fmt.Errorf("--after is required")
			}
			if resourceARN == "" {
				resourceARN = "*"
			}
			if action == "" {
				action = "*"
			}

			// Load both files
			beforeResult, err := simulation.LoadFromFile(beforeFile)
			if err != nil {
				return fmt.Errorf("failed to load before file: %w", err)
			}

			afterResult, err := simulation.LoadFromFile(afterFile)
			if err != nil {
				return fmt.Errorf("failed to load after file: %w", err)
			}

			// Build graphs
			beforeGraph, err := graph.Build(beforeResult)
			if err != nil {
				return fmt.Errorf("failed to build before graph: %w", err)
			}

			afterGraph, err := graph.Build(afterResult)
			if err != nil {
				return fmt.Errorf("failed to build after graph: %w", err)
			}

			// Compare access
			diff, err := simulation.CompareAccess(beforeGraph, afterGraph, resourceARN, action)
			if err != nil {
				return fmt.Errorf("failed to compare access: %w", err)
			}

			// Output results
			if format == "json" {
				data, err := json.MarshalIndent(diff, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal JSON: %w", err)
				}
				fmt.Println(string(data))
				return nil
			}

			// Text output
			fmt.Printf("Access Diff for %s (action: %s)\n\n", resourceARN, action)

			if len(diff.Granted) > 0 {
				fmt.Printf("✅ NEW ACCESS GRANTED (%d principals):\n", len(diff.Granted))
				for _, arn := range diff.Granted {
					fmt.Printf("  + %s\n", arn)
				}
				fmt.Println()
			}

			if len(diff.Revoked) > 0 {
				fmt.Printf("❌ ACCESS REVOKED (%d principals):\n", len(diff.Revoked))
				for _, arn := range diff.Revoked {
					fmt.Printf("  - %s\n", arn)
				}
				fmt.Println()
			}

			if len(diff.Unchanged) > 0 {
				fmt.Printf("➡️  UNCHANGED ACCESS (%d principals)\n", len(diff.Unchanged))
			}

			if len(diff.Granted) == 0 && len(diff.Revoked) == 0 {
				fmt.Println("No changes in access")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&beforeFile, "before", "", "Policy data before changes (JSON)")
	cmd.Flags().StringVar(&afterFile, "after", "", "Policy data after changes (JSON)")
	cmd.Flags().StringVar(&resourceARN, "resource", "*", "Resource ARN to check (default: *)")
	cmd.Flags().StringVar(&action, "action", "*", "Action to check (default: *)")

	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")

	return cmd
}

// simulateTestCmd implements the "simulate test" subcommand
func simulateTestCmd() *cobra.Command {
	var dataFile, addPolicyFile, principalARN string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test a policy change without deploying to AWS",
		Long: `Apply a policy change to local data and analyze the impact.
Shows what access the policy grants and any security concerns.`,
		Example: `  # Test adding a new policy
  aws-access-map simulate test \
    --data current.json \
    --add-policy new-role-policy.json \
    --principal "arn:aws:iam::123:role/MyRole"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate inputs
			if dataFile == "" {
				return fmt.Errorf("--data is required")
			}
			if addPolicyFile == "" {
				return fmt.Errorf("--add-policy is required")
			}
			if principalARN == "" {
				return fmt.Errorf("--principal is required")
			}

			// Load base data
			baseResult, err := simulation.LoadFromFile(dataFile)
			if err != nil {
				return fmt.Errorf("failed to load base data: %w", err)
			}

			// Load policy to add
			policyData, err := os.ReadFile(addPolicyFile)
			if err != nil {
				return fmt.Errorf("failed to read policy file: %w", err)
			}

			var newPolicy types.PolicyDocument
			if err := json.Unmarshal(policyData, &newPolicy); err != nil {
				return fmt.Errorf("failed to parse policy JSON: %w", err)
			}

			// Apply change
			changes := &simulation.PolicyChanges{
				UpdatePolicies: map[string][]types.PolicyDocument{
					principalARN: {newPolicy},
				},
			}

			modifiedResult, err := simulation.MergePolicyChanges(baseResult, changes)
			if err != nil {
				return fmt.Errorf("failed to apply changes: %w", err)
			}

			// Build graphs
			beforeGraph, err := graph.Build(baseResult)
			if err != nil {
				return fmt.Errorf("failed to build before graph: %w", err)
			}

			afterGraph, err := graph.Build(modifiedResult)
			if err != nil {
				return fmt.Errorf("failed to build after graph: %w", err)
			}

			// Output
			fmt.Println("🔍 Testing policy change...")
			fmt.Printf("Principal: %s\n", principalARN)
			fmt.Printf("New Policy: %s\n\n", addPolicyFile)

			// Check if new policy grants admin access
			afterQuery := query.New(afterGraph)
			adminPrincipals, _ := afterQuery.WhoCan("*", "*")

			for _, p := range adminPrincipals {
				if p.ARN == principalARN {
					fmt.Println("⚠️  WARNING: This policy grants full admin access (*:* on *)")
					break
				}
			}

			// Show access diff for all resources
			diff, _ := simulation.CompareAccess(beforeGraph, afterGraph, "*", "*")

			if len(diff.Granted) > 0 {
				fmt.Printf("\n✅ New access granted: %d resources/actions\n", len(diff.Granted))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&dataFile, "data", "", "Base policy data file (JSON)")
	cmd.Flags().StringVar(&addPolicyFile, "add-policy", "", "Policy to add (JSON file)")
	cmd.Flags().StringVar(&principalARN, "principal", "", "Principal ARN to modify")

	_ = cmd.MarkFlagRequired("data")
	_ = cmd.MarkFlagRequired("add-policy")
	_ = cmd.MarkFlagRequired("principal")

	return cmd
}

// simulateValidateCmd implements the "simulate validate" subcommand
func simulateValidateCmd() *cobra.Command {
	var dataFile string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check policies for security issues",
		Long: `Validate policies for common security issues:
  - Full admin access (*:* on *)
  - Overly permissive wildcards
  - Public access`,
		Example: `  # Validate policies
  aws-access-map simulate validate --data policies.json

  # Use in CI/CD (exits with code 1 if issues found)
  aws-access-map simulate validate --data proposed-policies.json || exit 1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate inputs
			if dataFile == "" {
				return fmt.Errorf("--data is required")
			}

			// Load data
			result, err := simulation.LoadFromFile(dataFile)
			if err != nil {
				return fmt.Errorf("failed to load data: %w", err)
			}

			// Build graph
			g, err := graph.Build(result)
			if err != nil {
				return fmt.Errorf("failed to build graph: %w", err)
			}

			// Create query engine
			q := query.New(g)

			issues := []string{}

			// Check 1: Full admin access
			adminPrincipals, err := q.WhoCan("*", "*")
			if err == nil && len(adminPrincipals) > 0 {
				issues = append(issues, fmt.Sprintf("⚠️  %d principals have full admin access (*:* on *)", len(adminPrincipals)))
				for _, p := range adminPrincipals {
					issues = append(issues, fmt.Sprintf("    - %s (%s)", p.Name, p.ARN))
				}
			}

			// Check 2: Public access (principals with Type "public" or "*" in ARN)
			publicCount := 0
			for _, principal := range result.Principals {
				if principal.Type == types.PrincipalTypePublic || principal.ARN == "*" {
					publicCount++
				}
			}
			if publicCount > 0 {
				issues = append(issues, fmt.Sprintf("⚠️  %d resources allow public access", publicCount))
			}

			// Check 3: Principals with no policies (potentially unused)
			unusedCount := 0
			for _, principal := range result.Principals {
				if len(principal.Policies) == 0 && principal.TrustPolicy == nil {
					unusedCount++
				}
			}
			if unusedCount > 0 {
				issues = append(issues, fmt.Sprintf("ℹ️  %d principals have no policies (potentially unused)", unusedCount))
			}

			// Output results
			if len(issues) > 0 {
				fmt.Println("Security Issues Found:")
				for _, issue := range issues {
					fmt.Println(issue)
				}
				os.Exit(1) // Non-zero exit for CI/CD
			} else {
				fmt.Println("✅ No security issues detected")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&dataFile, "data", "", "Policy data file (JSON)")

	_ = cmd.MarkFlagRequired("data")

	return cmd
}
