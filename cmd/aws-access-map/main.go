package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/pfrederiksen/aws-access-map/internal/collector"
	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/internal/query"
)

var (
	// Version information
	version = "0.1.0-mvp"

	// Global flags
	profile string
	debug   bool
	region  string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "aws-access-map",
		Short: "Instant 'who can reach this?' mapping for AWS resources",
		Long: `aws-access-map builds a graph query engine over IAM and resource policies
to answer access questions about your AWS infrastructure.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "AWS profile to use")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging")
	rootCmd.PersistentFlags().StringVar(&region, "region", "", "AWS region (defaults to profile region)")

	// Add commands
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(collectCmd())
	rootCmd.AddCommand(whoCanCmd())
	rootCmd.AddCommand(pathCmd())
	rootCmd.AddCommand(reportCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aws-access-map version %s\n", version)
			fmt.Println("Instant 'who can reach this?' mapping for AWS resources")
			fmt.Println("https://github.com/pfrederiksen/aws-access-map")
		},
	}
}

func collectCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect IAM and resource policy data from AWS",
		Long:  `Fetches IAM policies, resource policies, SCPs, and role trust policies from your AWS account.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCollect(outputFile)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "aws-access-data.json", "Output file for collected data")

	return cmd
}

func whoCanCmd() *cobra.Command {
	var action string

	cmd := &cobra.Command{
		Use:   "who-can <resource>",
		Short: "Find all principals that can perform an action on a resource",
		Long:  `Query which principals (users, roles, groups) can perform a specific action on a resource.`,
		Example: `  aws-access-map who-can s3://my-bucket --action s3:GetObject
  aws-access-map who-can arn:aws:kms:us-east-1:123456789012:key/abc --action kms:Decrypt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resource := args[0]
			if action == "" {
				return fmt.Errorf("--action is required")
			}
			return runWhoCan(resource, action)
		},
	}

	cmd.Flags().StringVar(&action, "action", "", "AWS action to check (e.g., s3:GetObject)")
	_ = cmd.MarkFlagRequired("action")

	return cmd
}

func pathCmd() *cobra.Command {
	var (
		from   string
		to     string
		action string
	)

	cmd := &cobra.Command{
		Use:   "path",
		Short: "[EXPERIMENTAL] Find access paths from a principal to a resource",
		Long:  `[EXPERIMENTAL] Discover all paths from a principal to a resource, including role assumption chains.

Note: This command is experimental. Currently only checks direct access.
Role assumption chains and transitive access are not yet implemented.`,
		Example: `  aws-access-map path \
    --from arn:aws:iam::123456789012:role/AppRole \
    --to arn:aws:s3:::sensitive-bucket \
    --action s3:GetObject`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" || to == "" || action == "" {
				return fmt.Errorf("--from, --to, and --action are all required")
			}
			return runPath(from, to, action)
		},
	}

	cmd.Flags().StringVar(&from, "from", "", "Source principal ARN")
	cmd.Flags().StringVar(&to, "to", "", "Target resource ARN or identifier")
	cmd.Flags().StringVar(&action, "action", "", "AWS action to check")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	_ = cmd.MarkFlagRequired("action")

	return cmd
}

func reportCmd() *cobra.Command {
	var (
		account  string
		highRisk bool
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "[COMING SOON] Generate security reports for AWS access",
		Long:  `[COMING SOON] Analyze collected data and generate reports highlighting high-risk access patterns.

Note: This command is not yet implemented. It will always return "No high-risk findings."
Use 'who-can "*" --action "*"' to find admin users manually for now.`,
		Example: `  aws-access-map report --account 123456789012 --high-risk`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(account, highRisk)
		},
	}

	cmd.Flags().StringVar(&account, "account", "", "AWS account ID to report on")
	cmd.Flags().BoolVar(&highRisk, "high-risk", false, "Only show high-risk findings")

	return cmd
}

func runCollect(outputFile string) error {
	ctx := context.Background()

	fmt.Println("Collecting AWS IAM data...")

	// Create collector
	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	// Collect data
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Printf("Collected %d principals\n", len(result.Principals))
	fmt.Printf("Collected %d resources\n", len(result.Resources))

	// Debug: Check statements before marshaling
	if debug && len(result.Principals) > 0 && len(result.Principals[0].Policies) > 0 {
		fmt.Printf("DEBUG: First principal has %d policies\n", len(result.Principals[0].Policies))
		fmt.Printf("DEBUG: First policy has %d statements\n", len(result.Principals[0].Policies[0].Statements))
	}

	// Save to file
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Data saved to %s\n", outputFile)
	return nil
}

func runWhoCan(resource, action string) error {
	ctx := context.Background()

	// For MVP, collect data on the fly
	// TODO: Load from cached file
	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Println("Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Println("Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Printf("Querying who can perform '%s' on '%s'...\n\n", action, resource)

	// Query the graph
	engine := query.New(g)
	principals, err := engine.WhoCan(resource, action)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

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

func runPath(from, to, action string) error {
	ctx := context.Background()

	// Collect data
	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Println("Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Println("Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Printf("Finding paths from '%s' to '%s' for action '%s'...\n\n", from, to, action)

	// Query the graph
	engine := query.New(g)
	paths, err := engine.FindPaths(from, to, action)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	if len(paths) == 0 {
		fmt.Println("No access paths found.")
		return nil
	}

	fmt.Printf("Found %d path(s):\n\n", len(paths))
	for i, path := range paths {
		fmt.Printf("Path %d:\n", i+1)
		for j, hop := range path.Hops {
			fmt.Printf("  %d. %s -[%s]-> %v\n", j+1, hop.From.Name, hop.Action, hop.To)
		}
		if len(path.Conditions) > 0 {
			fmt.Println("  Conditions:")
			for _, cond := range path.Conditions {
				fmt.Printf("    - %s\n", cond)
			}
		}
		fmt.Println()
	}

	return nil
}

func runReport(account string, highRisk bool) error {
	ctx := context.Background()

	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Println("Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Println("Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Println("Analyzing for high-risk patterns...")

	engine := query.New(g)
	findings, err := engine.FindHighRiskAccess()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

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
