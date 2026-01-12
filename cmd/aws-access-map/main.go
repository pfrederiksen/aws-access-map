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
	"github.com/pfrederiksen/aws-access-map/pkg/output"
)

var (
	// Version information
	version = "0.1.0-mvp"

	// Global flags
	profile string
	debug   bool
	region  string
	format  string
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
	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format (text|json)")

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
		Short: "Find access paths from a principal to a resource",
		Long:  `Discover all paths from a principal to a resource, including role assumption chains.

This command uses BFS to find both direct access and transitive access through role assumptions.
It will show all paths up to 5 hops (configurable max depth) and return up to 10 paths.`,
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
	// Validate format
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", format)
	}

	ctx := context.Background()

	// Send progress messages to stderr when using JSON format
	logOutput := os.Stdout
	if format == "json" {
		logOutput = os.Stderr
	}

	fmt.Fprintln(logOutput, "Collecting AWS IAM data...")

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

	// Debug: Check statements before marshaling
	if debug && len(result.Principals) > 0 && len(result.Principals[0].Policies) > 0 {
		fmt.Fprintf(logOutput, "DEBUG: First principal has %d policies\n", len(result.Principals[0].Policies))
		fmt.Fprintf(logOutput, "DEBUG: First policy has %d statements\n", len(result.Principals[0].Policies[0].Statements))
	}

	// Save to file (always save as JSON)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Print summary using output formatter
	return output.PrintCollect(format, result, outputFile)
}

func runWhoCan(resource, action string) error {
	// Validate format
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", format)
	}

	ctx := context.Background()

	// Send progress messages to stderr when using JSON format
	logOutput := os.Stdout
	if format == "json" {
		logOutput = os.Stderr
	}

	// For MVP, collect data on the fly
	// TODO: Load from cached file
	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Fprintln(logOutput, "Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Fprintln(logOutput, "Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Fprintf(logOutput, "Querying who can perform '%s' on '%s'...\n\n", action, resource)

	// Query the graph
	engine := query.New(g)
	principals, err := engine.WhoCan(resource, action)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	// Print results using output formatter
	return output.PrintWhoCan(format, resource, action, principals)
}

func runPath(from, to, action string) error {
	// Validate format
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", format)
	}

	ctx := context.Background()

	// Send progress messages to stderr when using JSON format
	logOutput := os.Stdout
	if format == "json" {
		logOutput = os.Stderr
	}

	// Collect data
	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Fprintln(logOutput, "Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Fprintln(logOutput, "Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Fprintf(logOutput, "Finding paths from '%s' to '%s' for action '%s'...\n\n", from, to, action)

	// Query the graph
	engine := query.New(g)
	paths, err := engine.FindPaths(from, to, action)
	if err != nil {
		return fmt.Errorf("query failed: %w", err)
	}

	// Print results using output formatter
	return output.PrintPaths(format, from, to, action, paths)
}

func runReport(account string, highRisk bool) error {
	// Validate format
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", format)
	}

	ctx := context.Background()

	// Send progress messages to stderr when using JSON format
	logOutput := os.Stdout
	if format == "json" {
		logOutput = os.Stderr
	}

	col, err := collector.New(ctx, region, profile, debug)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	fmt.Fprintln(logOutput, "Collecting AWS data...")
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect data: %w", err)
	}

	fmt.Fprintln(logOutput, "Building access graph...")
	g, err := graph.Build(result)
	if err != nil {
		return fmt.Errorf("failed to build graph: %w", err)
	}

	fmt.Fprintln(logOutput, "Analyzing for high-risk patterns...")

	engine := query.New(g)
	findings, err := engine.FindHighRiskAccess()
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Filter to only high-risk if flag is set
	if highRisk {
		filtered := make([]query.HighRiskFinding, 0)
		for _, f := range findings {
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Print results using output formatter
	return output.PrintReport(format, result.AccountID, findings)
}
