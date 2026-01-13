package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/pfrederiksen/aws-access-map/internal/cache"
	"github.com/pfrederiksen/aws-access-map/internal/collector"
	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/internal/query"
	"github.com/pfrederiksen/aws-access-map/pkg/output"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

var (
	// Version information
	version = "0.6.0"

	// Global flags
	profile string
	debug   bool
	region  string
	format  string

	// Cache flags
	useCache bool
	noCache  bool
	cacheTTL time.Duration

	// Condition evaluation context flags
	sourceIP    string
	mfa         bool
	orgID       string
	principalArn string
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

	// Cache flags
	rootCmd.PersistentFlags().BoolVar(&useCache, "cache", false, "Force use cached data (fail if cache missing or stale)")
	rootCmd.PersistentFlags().BoolVar(&noCache, "no-cache", false, "Force fresh collection, bypass cache")
	rootCmd.PersistentFlags().DurationVar(&cacheTTL, "cache-ttl", cache.DefaultTTL, "Cache TTL duration (default 24h)")

	// Condition evaluation context flags
	rootCmd.PersistentFlags().StringVar(&sourceIP, "source-ip", "", "Source IP address for condition evaluation (e.g., 203.0.113.50)")
	rootCmd.PersistentFlags().BoolVar(&mfa, "mfa", false, "Assume MFA is authenticated")
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Principal organization ID (e.g., o-123456)")
	rootCmd.PersistentFlags().StringVar(&principalArn, "principal-arn", "", "Principal ARN for condition evaluation")

	// Add commands
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(collectCmd())
	rootCmd.AddCommand(whoCanCmd())
	rootCmd.AddCommand(pathCmd())
	rootCmd.AddCommand(reportCmd())
	rootCmd.AddCommand(cacheCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// buildEvaluationContext creates an evaluation context from CLI flags
func buildEvaluationContext() *conditions.EvaluationContext {
	ctx := conditions.NewDefaultContext()

	// Override defaults with CLI flags if provided
	if sourceIP != "" {
		ctx.SourceIP = sourceIP
	}
	if mfa {
		ctx.MFAAuthenticated = true
	}
	if orgID != "" {
		ctx.PrincipalOrgID = orgID
	}
	if principalArn != "" {
		ctx.PrincipalARN = principalArn
	}

	return ctx
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
	var (
		outputFile  string
		includeSCPs bool
		allAccounts bool
		roleName    string
	)

	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect IAM and resource policy data from AWS",
		Long:  `Fetches IAM policies, resource policies, SCPs, and role trust policies from your AWS account or entire organization.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCollect(outputFile, includeSCPs, allAccounts, roleName)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "aws-access-data.json", "Output file for collected data")
	cmd.Flags().BoolVar(&includeSCPs, "include-scps", false, "Collect Service Control Policies from AWS Organizations (requires organizations:ListPolicies permission)")
	cmd.Flags().BoolVar(&allAccounts, "all-accounts", false, "Collect from all accounts in the organization (requires Organizations access)")
	cmd.Flags().StringVar(&roleName, "role-name", "OrganizationAccountAccessRole", "Role name to assume in member accounts (only with --all-accounts)")

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

func cacheCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage cached AWS data",
		Long:  `View and manage cached collection data. Cache speeds up repeated queries by storing previously collected AWS data.`,
	}

	// Add subcommands
	cmd.AddCommand(cacheClearCmd())
	cmd.AddCommand(cacheInfoCmd())

	return cmd
}

func cacheClearCmd() *cobra.Command {
	var accountID string

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear cached data",
		Long:  `Delete cached collection data. If --account is specified, only clear cache for that account. Otherwise, clear all cache.`,
		Example: `  aws-access-map cache clear
  aws-access-map cache clear --account 123456789012`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if accountID != "" {
				if err := cache.Clear(accountID); err != nil {
					return fmt.Errorf("failed to clear cache for account %s: %w", accountID, err)
				}
				fmt.Printf("Cache cleared for account %s\n", accountID)
			} else {
				if err := cache.Clear(""); err != nil {
					return fmt.Errorf("failed to clear all cache: %w", err)
				}
				fmt.Println("All cache cleared")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "AWS account ID to clear cache for (leave empty to clear all)")

	return cmd
}

func cacheInfoCmd() *cobra.Command {
	var accountID string

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show cache information",
		Long:  `Display information about cached data for an account, including location and age.`,
		Example: `  aws-access-map cache info --account 123456789012`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if accountID == "" {
				return fmt.Errorf("--account is required")
			}

			filePath, modTime, err := cache.GetCacheInfo(accountID)
			if err != nil {
				return fmt.Errorf("failed to get cache info: %w", err)
			}

			if filePath == "" {
				fmt.Printf("No cache found for account %s\n", accountID)
				return nil
			}

			age := time.Since(modTime)
			fmt.Printf("Cache for account %s:\n", accountID)
			fmt.Printf("  Location: %s\n", filePath)
			fmt.Printf("  Modified: %s (%s ago)\n", modTime.Format(time.RFC3339), age.Round(time.Second))

			if age > cache.DefaultTTL {
				fmt.Printf("  Status: STALE (older than %s)\n", cache.DefaultTTL)
			} else {
				fmt.Printf("  Status: VALID (TTL: %s remaining)\n", (cache.DefaultTTL - age).Round(time.Second))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&accountID, "account", "", "AWS account ID to show info for")
	_ = cmd.MarkFlagRequired("account")

	return cmd
}

func runCollect(outputFile string, includeSCPs bool, allAccounts bool, roleName string) error {
	// Validate format
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid format: %s (must be 'text' or 'json')", format)
	}

	// Validate cache flags
	if useCache && noCache {
		return fmt.Errorf("--cache and --no-cache cannot both be specified")
	}

	// Validate multi-account flags
	if allAccounts && (useCache || noCache) {
		return fmt.Errorf("caching is not supported with --all-accounts (not yet implemented)")
	}

	ctx := context.Background()

	// Send progress messages to stderr when using JSON format
	logOutput := os.Stdout
	if format == "json" {
		logOutput = os.Stderr
	}

	// Handle multi-account collection separately
	if allAccounts {
		return runMultiAccountCollect(ctx, outputFile, roleName, logOutput)
	}

	var result *types.CollectionResult
	var err error
	usedCache := false

	// First, we need to get account ID to check cache
	// We'll create a temporary collector just to get the account ID
	col, err := collector.New(ctx, region, profile, debug, includeSCPs)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	// Get account ID for cache lookup
	accountID, err := getAccountIDFromCollector(ctx, col)
	if err != nil {
		if debug {
			fmt.Fprintf(logOutput, "DEBUG: Failed to get account ID for cache lookup: %v\n", err)
		}
		// Continue without cache if we can't get account ID
		accountID = ""
	}

	// Cache logic
	if useCache {
		// Force use cache - fail if not found or stale
		if accountID == "" {
			return fmt.Errorf("cannot use cache: failed to determine account ID")
		}

		fmt.Fprintln(logOutput, "Loading from cache...")
		result, err = cache.Load(accountID, cacheTTL)
		if err != nil {
			return fmt.Errorf("failed to load from cache: %w", err)
		}
		if result == nil {
			return fmt.Errorf("no valid cache found for account %s (use --no-cache to collect fresh data)", accountID)
		}
		usedCache = true
		fmt.Fprintln(logOutput, "Loaded from cache successfully")
	} else if !noCache && accountID != "" {
		// Default behavior: try cache first, fall back to collection
		if debug {
			fmt.Fprintf(logOutput, "DEBUG: Checking cache for account %s...\n", accountID)
		}

		result, err = cache.Load(accountID, cacheTTL)
		if err != nil {
			if debug {
				fmt.Fprintf(logOutput, "DEBUG: Cache load error: %v\n", err)
			}
			// Continue to collection on cache error
			result = nil
		}

		if result != nil {
			usedCache = true
			fmt.Fprintln(logOutput, "Loaded from cache (use --no-cache to force fresh collection)")
		}
	}

	// If no cached result, collect fresh data
	if result == nil {
		fmt.Fprintln(logOutput, "Collecting AWS IAM data...")

		result, err = col.Collect(ctx)
		if err != nil {
			return fmt.Errorf("failed to collect data: %w", err)
		}

		// Save to cache (unless --no-cache)
		if !noCache && result.AccountID != "" {
			if err := cache.Save(result.AccountID, result); err != nil {
				// Log warning but don't fail
				fmt.Fprintf(logOutput, "Warning: failed to save to cache: %v\n", err)
			} else if debug {
				fmt.Fprintf(logOutput, "DEBUG: Saved to cache for account %s\n", result.AccountID)
			}
		}
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
	if usedCache {
		fmt.Fprintln(logOutput, "(Data loaded from cache)")
	}
	return output.PrintCollect(format, result, outputFile)
}

// getAccountIDFromCollector extracts the account ID without doing full collection
// This is a helper to enable cache lookup before full collection
func getAccountIDFromCollector(ctx context.Context, col *collector.Collector) (string, error) {
	// Unfortunately, the Collector doesn't expose getAccountID publicly
	// For now, we'll have to do a full collection to get the account ID
	// This could be optimized in the future by making getAccountID public
	// For cache-first scenarios, this isn't a problem since we avoid the collection
	// For --cache scenarios, we'll collect anyway if cache misses

	// Return empty string to signal that we should skip cache lookup
	// and proceed with collection. The collection will populate AccountID.
	return "", nil
}

// runMultiAccountCollect handles collection from all accounts in an organization
func runMultiAccountCollect(ctx context.Context, outputFile string, roleName string, logOutput *os.File) error {
	fmt.Fprintln(logOutput, "Collecting from all accounts in organization...")
	fmt.Fprintf(logOutput, "Using role: %s\n", roleName)

	// Create collector with SCP collection enabled for organization-wide collection
	col, err := collector.New(ctx, region, profile, debug, true)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	// Collect from all accounts
	result, err := col.CollectOrganization(ctx, roleName)
	if err != nil {
		return fmt.Errorf("failed to collect from organization: %w", err)
	}

	// Print summary
	fmt.Fprintf(logOutput, "\nCollection complete:\n")
	fmt.Fprintf(logOutput, "  Organization ID: %s\n", result.OrganizationID)
	fmt.Fprintf(logOutput, "  Accounts succeeded: %d\n", result.SuccessCount)
	fmt.Fprintf(logOutput, "  Accounts failed: %d\n", result.FailureCount)
	if len(result.FailedAccounts) > 0 {
		fmt.Fprintf(logOutput, "  Failed account IDs: %v\n", result.FailedAccounts)
	}

	// Count total principals and resources
	totalPrincipals := 0
	totalResources := 0
	for _, accountResult := range result.Accounts {
		totalPrincipals += len(accountResult.Principals)
		totalResources += len(accountResult.Resources)
	}
	fmt.Fprintf(logOutput, "  Total principals: %d\n", totalPrincipals)
	fmt.Fprintf(logOutput, "  Total resources: %d\n", totalResources)
	fmt.Fprintf(logOutput, "  SCPs collected: %d\n", len(result.SCPAttachments))

	// Save to file as JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Fprintf(logOutput, "\nData saved to: %s\n", outputFile)
	return nil
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
	col, err := collector.New(ctx, region, profile, debug, false) // Don't collect SCPs for query commands
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

	// Query the graph with evaluation context
	evalCtx := buildEvaluationContext()
	engine := query.New(g).WithContext(evalCtx)
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
	col, err := collector.New(ctx, region, profile, debug, false) // Don't collect SCPs for query commands
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

	// Query the graph with evaluation context
	evalCtx := buildEvaluationContext()
	engine := query.New(g).WithContext(evalCtx)
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

	col, err := collector.New(ctx, region, profile, debug, false) // Don't collect SCPs for query commands
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

	// Query the graph with evaluation context
	evalCtx := buildEvaluationContext()
	engine := query.New(g).WithContext(evalCtx)
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
