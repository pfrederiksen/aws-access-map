# Implementation Plan: JSON Output + Resource Policies + Report Command

## Overview

This plan covers the implementation of three high-priority features in sequence:

1. **JSON Output Mode** (Feature #3) - Add `--format json` flag to all commands
2. **Resource Policy Collection** (Feature #1) - Collect S3, KMS, SQS, SNS, Secrets Manager policies
3. **Report Command Implementation** (Feature #4) - Generate security audit reports

## Feature #1: JSON Output Mode

### Goal
Enable structured JSON output for all commands to support automation, CI/CD integration, and programmatic consumption.

### Current State
- All commands (`who-can`, `path`, `report`, `collect`) print human-readable text to stdout
- No structured output available for scripting
- Example current output:
  ```
  Found 2 principal(s) with access:

    admin (user)
      ARN: arn:aws:iam::123456789012:user/admin
  ```

### Proposed Changes

#### 1. Add Global `--format` Flag
**File:** `cmd/aws-access-map/main.go`
- Add `format string` global variable (default: "text")
- Add flag: `rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format (text|json)")`
- Validate format is either "text" or "json"

#### 2. Define JSON Output Structures
**New File:** `pkg/output/types.go`
```go
type WhoCanOutput struct {
    Resource   string              `json:"resource"`
    Action     string              `json:"action"`
    Principals []PrincipalOutput   `json:"principals"`
}

type PrincipalOutput struct {
    ARN         string   `json:"arn"`
    Type        string   `json:"type"`
    Name        string   `json:"name"`
    AccountID   string   `json:"account_id,omitempty"`
}

type PathsOutput struct {
    From   string          `json:"from"`
    To     string          `json:"to"`
    Action string          `json:"action"`
    Paths  []PathOutput    `json:"paths"`
}

type PathOutput struct {
    Hops       []HopOutput   `json:"hops"`
    Conditions []string      `json:"conditions,omitempty"`
}

type HopOutput struct {
    From        PrincipalOutput `json:"from"`
    To          interface{}     `json:"to"` // Can be principal or resource
    Action      string          `json:"action"`
    PolicyType  string          `json:"policy_type"`
}

type ReportOutput struct {
    AccountID  string              `json:"account_id"`
    GeneratedAt string             `json:"generated_at"`
    Findings   []FindingOutput     `json:"findings"`
}

type FindingOutput struct {
    Type        string               `json:"type"`
    Severity    string               `json:"severity"`
    Description string               `json:"description"`
    Principal   *PrincipalOutput     `json:"principal,omitempty"`
    Resource    *ResourceOutput      `json:"resource,omitempty"`
    Action      string               `json:"action,omitempty"`
}

type ResourceOutput struct {
    ARN       string `json:"arn"`
    Type      string `json:"type"`
    Name      string `json:"name"`
    Region    string `json:"region,omitempty"`
    AccountID string `json:"account_id,omitempty"`
}
```

#### 3. Create Output Formatter Helper
**New File:** `pkg/output/formatter.go`
```go
func PrintWhoCan(format string, resource, action string, principals []*types.Principal) error {
    if format == "json" {
        return printWhoCanJSON(resource, action, principals)
    }
    return printWhoCanText(resource, action, principals)
}

func PrintPaths(format string, from, to, action string, paths []*types.AccessPath) error {
    if format == "json" {
        return printPathsJSON(from, to, action, paths)
    }
    return printPathsText(from, to, action, paths)
}

func PrintReport(format string, accountID string, findings []query.HighRiskFinding) error {
    if format == "json" {
        return printReportJSON(accountID, findings)
    }
    return printReportText(accountID, findings)
}
```

#### 4. Update Commands to Use Formatter
**File:** `cmd/aws-access-map/main.go`
- Replace direct `fmt.Printf` calls in `runWhoCan()`, `runPath()`, `runReport()`
- Use `output.PrintWhoCan(format, resource, action, principals)`
- Preserve progress messages to stderr when format is JSON: `fmt.Fprintln(os.Stderr, "Collecting AWS data...")`

#### 5. Testing
**New File:** `pkg/output/formatter_test.go`
- Test JSON output is valid JSON (use `json.Unmarshal` to validate)
- Test all fields are populated correctly
- Test text output matches current format
- Test empty results (no principals found)

### Success Criteria
- `aws-access-map who-can s3://bucket --action s3:GetObject --format json` outputs valid JSON
- All fields in JSON output are populated
- Text output remains unchanged (default)
- Progress messages go to stderr when JSON format is used
- All commands support both formats

---

## Feature #2: Resource Policy Collection

### Goal
Collect and evaluate resource-based policies from S3, KMS, SQS, SNS, and Secrets Manager. This fixes a critical blind spot where access granted via resource policies is currently invisible.

### Current State
- Only identity-based policies are collected (user/role policies)
- Resource policies are not collected (see TODO in `collector.go:75`)
- Graph builder has TODO for processing resource policies (`graph.go:68`)
- `CollectionResult.Resources` is always empty

### Proposed Changes

#### 1. Add AWS Service Clients
**File:** `internal/collector/collector.go`
```go
import (
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/aws/aws-sdk-go-v2/service/sqs"
    "github.com/aws/aws-sdk-go-v2/service/sns"
    "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type Collector struct {
    iamClient            *iam.Client
    s3Client             *s3.Client
    kmsClient            *kms.Client
    sqsClient            *sqs.Client
    snsClient            *sns.Client
    secretsManagerClient *secretsmanager.Client
    region               string
    profile              string
    debug                bool
}
```

#### 2. Implement S3 Bucket Policy Collection
**File:** `internal/collector/s3.go` (new file)
```go
func (c *Collector) collectS3Resources(ctx context.Context) ([]*types.Resource, error) {
    var resources []*types.Resource

    // List all buckets
    output, err := c.s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
    if err != nil {
        return nil, fmt.Errorf("failed to list S3 buckets: %w", err)
    }

    for _, bucket := range output.Buckets {
        resource := &types.Resource{
            ARN:       fmt.Sprintf("arn:aws:s3:::%s", *bucket.Name),
            Type:      types.ResourceTypeS3,
            Name:      *bucket.Name,
            Region:    c.region,
            AccountID: "", // S3 doesn't expose this directly
        }

        // Get bucket policy
        policyOutput, err := c.s3Client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
            Bucket: bucket.Name,
        })

        // Bucket may not have a policy - that's OK
        if err == nil && policyOutput.Policy != nil {
            policy, err := c.parsePolicy(*policyOutput.Policy)
            if err != nil {
                return nil, fmt.Errorf("failed to parse policy for bucket %s: %w", *bucket.Name, err)
            }
            resource.ResourcePolicy = policy
        }

        resources = append(resources, resource)
    }

    return resources, nil
}
```

#### 3. Implement KMS Key Policy Collection
**File:** `internal/collector/kms.go` (new file)
```go
func (c *Collector) collectKMSResources(ctx context.Context) ([]*types.Resource, error) {
    var resources []*types.Resource

    // List KMS keys
    paginator := kms.NewListKeysPaginator(c.kmsClient, &kms.ListKeysInput{})

    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("failed to list KMS keys: %w", err)
        }

        for _, key := range output.Keys {
            // Get key details
            keyOutput, err := c.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
                KeyId: key.KeyId,
            })
            if err != nil {
                continue // Skip keys we can't access
            }

            resource := &types.Resource{
                ARN:       *keyOutput.KeyMetadata.Arn,
                Type:      types.ResourceTypeKMS,
                Name:      *key.KeyId,
                Region:    c.region,
                AccountID: *keyOutput.KeyMetadata.AWSAccountId,
            }

            // Get key policy
            policyOutput, err := c.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
                KeyId:      key.KeyId,
                PolicyName: aws.String("default"),
            })

            if err == nil && policyOutput.Policy != nil {
                policy, err := c.parsePolicy(*policyOutput.Policy)
                if err != nil {
                    return nil, fmt.Errorf("failed to parse policy for KMS key %s: %w", *key.KeyId, err)
                }
                resource.ResourcePolicy = policy
            }

            resources = append(resources, resource)
        }
    }

    return resources, nil
}
```

#### 4. Implement SQS Queue Policy Collection
**File:** `internal/collector/sqs.go` (new file)
```go
func (c *Collector) collectSQSResources(ctx context.Context) ([]*types.Resource, error) {
    var resources []*types.Resource

    // List queues
    paginator := sqs.NewListQueuesPaginator(c.sqsClient, &sqs.ListQueuesInput{})

    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("failed to list SQS queues: %w", err)
        }

        for _, queueUrl := range output.QueueUrls {
            // Get queue attributes including policy
            attrs, err := c.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
                QueueUrl: &queueUrl,
                AttributeNames: []types.QueueAttributeName{
                    types.QueueAttributeNameQueueArn,
                    types.QueueAttributeNamePolicy,
                },
            })

            if err != nil {
                continue
            }

            queueArn := attrs.Attributes["QueueArn"]
            resource := &types.Resource{
                ARN:    queueArn,
                Type:   types.ResourceTypeSQS,
                Name:   extractQueueName(queueUrl),
                Region: c.region,
            }

            // Parse policy if present
            if policyStr, ok := attrs.Attributes["Policy"]; ok && policyStr != "" {
                policy, err := c.parsePolicy(policyStr)
                if err != nil {
                    return nil, fmt.Errorf("failed to parse policy for queue %s: %w", queueUrl, err)
                }
                resource.ResourcePolicy = policy
            }

            resources = append(resources, resource)
        }
    }

    return resources, nil
}
```

#### 5. Implement SNS Topic Policy Collection
**File:** `internal/collector/sns.go` (new file)
```go
func (c *Collector) collectSNSResources(ctx context.Context) ([]*types.Resource, error) {
    var resources []*types.Resource

    // List topics
    paginator := sns.NewListTopicsPaginator(c.snsClient, &sns.ListTopicsInput{})

    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("failed to list SNS topics: %w", err)
        }

        for _, topic := range output.Topics {
            // Get topic attributes including policy
            attrs, err := c.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
                TopicArn: topic.TopicArn,
            })

            if err != nil {
                continue
            }

            resource := &types.Resource{
                ARN:    *topic.TopicArn,
                Type:   types.ResourceTypeSNS,
                Name:   extractTopicName(*topic.TopicArn),
                Region: c.region,
            }

            // Parse policy if present
            if policyStr, ok := attrs.Attributes["Policy"]; ok && policyStr != "" {
                policy, err := c.parsePolicy(policyStr)
                if err != nil {
                    return nil, fmt.Errorf("failed to parse policy for topic %s: %w", *topic.TopicArn, err)
                }
                resource.ResourcePolicy = policy
            }

            resources = append(resources, resource)
        }
    }

    return resources, nil
}
```

#### 6. Implement Secrets Manager Policy Collection
**File:** `internal/collector/secretsmanager.go` (new file)
```go
func (c *Collector) collectSecretsManagerResources(ctx context.Context) ([]*types.Resource, error) {
    var resources []*types.Resource

    // List secrets
    paginator := secretsmanager.NewListSecretsPaginator(c.secretsManagerClient, &secretsmanager.ListSecretsInput{})

    for paginator.HasMorePages() {
        output, err := paginator.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("failed to list secrets: %w", err)
        }

        for _, secret := range output.SecretList {
            resource := &types.Resource{
                ARN:    *secret.ARN,
                Type:   types.ResourceTypeSecretsManager,
                Name:   *secret.Name,
                Region: c.region,
            }

            // Get resource policy
            policyOutput, err := c.secretsManagerClient.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
                SecretId: secret.ARN,
            })

            if err == nil && policyOutput.ResourcePolicy != nil {
                policy, err := c.parsePolicy(*policyOutput.ResourcePolicy)
                if err != nil {
                    return nil, fmt.Errorf("failed to parse policy for secret %s: %w", *secret.Name, err)
                }
                resource.ResourcePolicy = policy
            }

            resources = append(resources, resource)
        }
    }

    return resources, nil
}
```

#### 7. Update Main Collector
**File:** `internal/collector/collector.go`
```go
func (c *Collector) Collect(ctx context.Context) (*types.CollectionResult, error) {
    result := &types.CollectionResult{
        Regions: []string{c.region},
    }

    // ... existing IAM collection ...

    // Collect resource policies
    s3Resources, err := c.collectS3Resources(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect S3 resources: %w", err)
    }
    result.Resources = append(result.Resources, s3Resources...)

    kmsResources, err := c.collectKMSResources(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect KMS resources: %w", err)
    }
    result.Resources = append(result.Resources, kmsResources...)

    sqsResources, err := c.collectSQSResources(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect SQS resources: %w", err)
    }
    result.Resources = append(result.Resources, sqsResources...)

    snsResources, err := c.collectSNSResources(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect SNS resources: %w", err)
    }
    result.Resources = append(result.Resources, snsResources...)

    secretsResources, err := c.collectSecretsManagerResources(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect Secrets Manager resources: %w", err)
    }
    result.Resources = append(result.Resources, secretsResources...)

    return result, nil
}
```

#### 8. Update Graph Builder to Process Resource Policies
**File:** `internal/graph/graph.go`
```go
// In Build() function, after adding resources:
for _, resource := range collection.Resources {
    g.AddResource(resource)

    // Process resource policies
    if resource.ResourcePolicy != nil {
        if err := g.addResourcePolicyEdges(resource.ARN, *resource.ResourcePolicy); err != nil {
            return nil, fmt.Errorf("failed to process resource policy for %s: %w", resource.ARN, err)
        }
    }
}
```

```go
// New function to add resource policy edges
func (g *Graph) addResourcePolicyEdges(resourceARN string, policy types.PolicyDocument) error {
    for _, stmt := range policy.Statements {
        if stmt.Effect != types.EffectAllow {
            continue // Only process Allow statements for now
        }

        // Extract principals allowed by this resource policy
        principals := extractPrincipals(stmt.Principal)
        actions := normalizeToSlice(stmt.Action)

        for _, principalARN := range principals {
            for _, action := range actions {
                // Add edge from principal to resource
                g.AddEdge(principalARN, action, resourceARN, false)
            }
        }
    }
    return nil
}
```

#### 9. Handle Wildcard Principals (Public Access)
**File:** `internal/graph/graph.go`
```go
// When adding edges from resource policies, check for "*" principal
if principalARN == "*" || principalARN == "arn:aws:iam::*:root" {
    // Create synthetic "public" principal if it doesn't exist
    if _, ok := g.GetPrincipal("*"); !ok {
        publicPrincipal := &types.Principal{
            ARN:  "*",
            Type: types.PrincipalTypePublic,
            Name: "Public (Anonymous)",
        }
        g.AddPrincipal(publicPrincipal)
    }
}
```

#### 10. Update go.mod Dependencies
```bash
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/aws/aws-sdk-go-v2/service/kms
go get github.com/aws/aws-sdk-go-v2/service/sqs
go get github.com/aws/aws-sdk-go-v2/service/sns
go get github.com/aws/aws-sdk-go-v2/service/secretsmanager
```

#### 11. Testing
**New Files:**
- `internal/collector/s3_test.go`
- `internal/collector/kms_test.go`
- `internal/collector/sqs_test.go`
- `internal/collector/sns_test.go`
- `internal/collector/secretsmanager_test.go`

Test cases:
- Bucket with policy granting public read access
- KMS key with cross-account access
- SQS queue with service principal access
- SNS topic with account-level access
- Secret with resource policy

**Integration test:**
Create test resources with known policies, run collector, verify resource policies are captured.

### Success Criteria
- `aws-access-map collect` returns resources with policies
- `aws-access-map who-can s3://bucket --action s3:GetObject` finds principals granted access via bucket policy
- Public access (*) is detected and shown
- Resource policy permissions merge correctly with identity policy permissions

---

## Feature #3: Report Command Implementation

### Goal
Implement the `report` command to generate security audit reports identifying high-risk access patterns.

### Current State
- `runReport()` is stubbed and always returns "No high-risk findings"
- `FindHighRiskAccess()` in query engine returns empty slice

### High-Risk Patterns to Detect

1. **Admin Access (Wildcard Permissions)**
   - Principals with `Action: "*"` and `Resource: "*"`
   - Severity: CRITICAL

2. **Public Resource Access**
   - Resources with policies allowing `Principal: "*"`
   - Severity: HIGH (for sensitive resources), MEDIUM (for public-facing resources)

3. **Cross-Account Access**
   - Principals from external AWS accounts
   - Extract from resource policies and trust policies
   - Severity: MEDIUM

4. **Overly Permissive S3 Access**
   - Principals with `s3:*` on all buckets
   - Public S3 bucket access
   - Severity: HIGH

5. **Sensitive Action Access**
   - `iam:*` (IAM admin)
   - `kms:Decrypt` on all keys
   - `secretsmanager:GetSecretValue` on all secrets
   - Severity: HIGH

6. **Long Role Assumption Chains**
   - Paths with more than 3 hops (indicates complex permissions)
   - Severity: LOW (informational)

### Proposed Changes

#### 1. Implement FindHighRiskAccess
**File:** `internal/query/query.go`
```go
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

func (e *Engine) findAdminAccess() []HighRiskFinding {
    var findings []HighRiskFinding

    // Check all principals for wildcard permissions
    for _, principal := range e.graph.GetAllPrincipals() {
        if e.graph.CanAccess(principal.ARN, "*", "*") {
            findings = append(findings, HighRiskFinding{
                Type:        "Admin Access",
                Severity:    "CRITICAL",
                Description: fmt.Sprintf("Principal %s has unrestricted admin access (* on *)", principal.Name),
                Principal:   principal,
                Action:      "*",
            })
        }
    }

    return findings
}

func (e *Engine) findPublicResourceAccess() []HighRiskFinding {
    var findings []HighRiskFinding

    // Check for public principal
    publicPrincipal, ok := e.graph.GetPrincipal("*")
    if !ok {
        return findings
    }

    // Find all resources accessible by public principal
    for _, resource := range e.graph.GetAllResources() {
        if e.graph.CanAccess(publicPrincipal.ARN, "*", resource.ARN) {
            severity := "HIGH"
            if resource.Type == types.ResourceTypeS3 {
                severity = "CRITICAL" // Public S3 is very risky
            }

            findings = append(findings, HighRiskFinding{
                Type:        "Public Access",
                Severity:    severity,
                Description: fmt.Sprintf("Resource %s allows public access", resource.Name),
                Principal:   publicPrincipal,
                Resource:    resource,
                Action:      "*",
            })
        }
    }

    return findings
}

func (e *Engine) findCrossAccountAccess() []HighRiskFinding {
    var findings []HighRiskFinding

    // Get local account ID from first principal
    var localAccountID string
    for _, p := range e.graph.GetAllPrincipals() {
        localAccountID = p.AccountID
        break
    }

    // Check all principals for external account IDs
    for _, principal := range e.graph.GetAllPrincipals() {
        if principal.AccountID != "" && principal.AccountID != localAccountID {
            findings = append(findings, HighRiskFinding{
                Type:        "Cross-Account Access",
                Severity:    "MEDIUM",
                Description: fmt.Sprintf("Principal %s from account %s has access", principal.Name, principal.AccountID),
                Principal:   principal,
            })
        }
    }

    return findings
}

func (e *Engine) findOverlyPermissiveS3Access() []HighRiskFinding {
    var findings []HighRiskFinding

    for _, principal := range e.graph.GetAllPrincipals() {
        // Check for s3:* on all resources
        if e.graph.CanAccess(principal.ARN, "s3:*", "*") {
            findings = append(findings, HighRiskFinding{
                Type:        "Overly Permissive S3 Access",
                Severity:    "HIGH",
                Description: fmt.Sprintf("Principal %s has full S3 access on all buckets", principal.Name),
                Principal:   principal,
                Action:      "s3:*",
            })
        }
    }

    return findings
}

func (e *Engine) findSensitiveActionAccess() []HighRiskFinding {
    var findings []HighRiskFinding

    sensitiveActions := map[string]string{
        "iam:*":                         "Full IAM access",
        "kms:Decrypt":                   "KMS decryption access",
        "secretsmanager:GetSecretValue": "Secrets retrieval access",
        "sts:AssumeRole":                "Role assumption access",
    }

    for _, principal := range e.graph.GetAllPrincipals() {
        for action, description := range sensitiveActions {
            if e.graph.CanAccess(principal.ARN, action, "*") {
                findings = append(findings, HighRiskFinding{
                    Type:        "Sensitive Action Access",
                    Severity:    "HIGH",
                    Description: fmt.Sprintf("Principal %s has %s on all resources", principal.Name, description),
                    Principal:   principal,
                    Action:      action,
                })
            }
        }
    }

    return findings
}
```

#### 2. Add GetAllResources to Graph
**File:** `internal/graph/graph.go`
```go
func (g *Graph) GetAllResources() []*types.Resource {
    g.mu.RLock()
    defer g.mu.RUnlock()

    resources := make([]*types.Resource, 0, len(g.resources))
    for _, r := range g.resources {
        resources = append(resources, r)
    }
    return resources
}
```

#### 3. Update runReport in main.go
**File:** `cmd/aws-access-map/main.go`
```go
func runReport(account string, highRisk bool) error {
    ctx := context.Background()

    col, err := collector.New(ctx, region, profile, debug)
    if err != nil {
        return fmt.Errorf("failed to create collector: %w", err)
    }

    fmt.Fprintln(os.Stderr, "Collecting AWS data...")
    result, err := col.Collect(ctx)
    if err != nil {
        return fmt.Errorf("failed to collect data: %w", err)
    }

    fmt.Fprintln(os.Stderr, "Building access graph...")
    g, err := graph.Build(result)
    if err != nil {
        return fmt.Errorf("failed to build graph: %w", err)
    }

    fmt.Fprintln(os.Stderr, "Analyzing for high-risk patterns...")

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

    // Use output formatter
    return output.PrintReport(format, result.AccountID, findings)
}
```

#### 4. Testing
**File:** `internal/query/report_test.go` (new file)
```go
func TestFindHighRiskAccess_AdminUser(t *testing.T) {
    g := graph.New()
    admin := &types.Principal{
        ARN:  "arn:aws:iam::123456789012:user/admin",
        Type: types.PrincipalTypeUser,
        Name: "admin",
    }
    g.AddPrincipal(admin)
    g.AddEdge(admin.ARN, "*", "*", false)

    e := New(g)
    findings, err := e.FindHighRiskAccess()

    if err != nil {
        t.Fatalf("FindHighRiskAccess() error = %v", err)
    }

    if len(findings) == 0 {
        t.Fatal("Expected to find admin access risk")
    }

    found := false
    for _, f := range findings {
        if f.Type == "Admin Access" && f.Severity == "CRITICAL" {
            found = true
            break
        }
    }

    if !found {
        t.Error("Did not find CRITICAL admin access finding")
    }
}

func TestFindHighRiskAccess_PublicS3Bucket(t *testing.T) {
    g := graph.New()

    // Create public principal
    publicPrincipal := &types.Principal{
        ARN:  "*",
        Type: types.PrincipalTypePublic,
        Name: "Public",
    }
    g.AddPrincipal(publicPrincipal)

    // Create S3 bucket with public access
    bucket := &types.Resource{
        ARN:  "arn:aws:s3:::public-bucket",
        Type: types.ResourceTypeS3,
        Name: "public-bucket",
    }
    g.AddResource(bucket)
    g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

    e := New(g)
    findings, err := e.FindHighRiskAccess()

    if err != nil {
        t.Fatalf("FindHighRiskAccess() error = %v", err)
    }

    found := false
    for _, f := range findings {
        if f.Type == "Public Access" && f.Resource != nil && f.Resource.Name == "public-bucket" {
            found = true
            break
        }
    }

    if !found {
        t.Error("Did not find public S3 bucket finding")
    }
}
```

### Success Criteria
- `aws-access-map report` returns meaningful findings
- Admin users are flagged as CRITICAL
- Public resources are flagged as HIGH/CRITICAL
- Cross-account access is detected
- `--format json` works with report command
- `--high-risk` flag filters to only HIGH and CRITICAL findings

---

## Implementation Order

### Phase 1: JSON Output (Estimated: 2-3 hours)
1. Create `pkg/output/` package with types and formatter
2. Add `--format` flag to main.go
3. Update all command run functions to use formatter
4. Write tests for JSON output
5. Test with real AWS data

### Phase 2: Resource Policies (Estimated: 4-6 hours)
1. Add AWS SDK dependencies
2. Implement S3 collector
3. Implement KMS collector
4. Implement SQS collector
5. Implement SNS collector
6. Implement Secrets Manager collector
7. Update graph builder to process resource policies
8. Handle public (*) principal
9. Write comprehensive tests
10. Test with real AWS resources

### Phase 3: Report Command (Estimated: 3-4 hours)
1. Implement FindHighRiskAccess patterns (admin, public, cross-account, S3, sensitive)
2. Add GetAllResources to graph
3. Update runReport in main.go
4. Integrate with JSON output formatter
5. Write tests for each finding type
6. Test with real AWS account

### Total Estimated Time: 9-13 hours

## Testing Strategy

### Unit Tests
- Each new function must have corresponding unit tests
- Use table-driven tests for pattern matching
- Mock AWS SDK responses for collector tests
- Aim for 90%+ coverage (maintain existing standard)

### Integration Tests
- Test full flow: collect → build graph → query
- Use testdata/ directory for realistic policy examples
- Test JSON output can be parsed back into Go structs

### Manual Testing
- Test against real AWS account (sandbox/test account)
- Verify all resource types are collected
- Verify report findings match manual inspection
- Test JSON output with jq for scripting

## Risks and Mitigations

### Risk 1: AWS API Rate Limiting
**Mitigation:**
- Implement exponential backoff for API calls
- Add `--resources` flag to selectively collect resource types
- Consider parallel collection with concurrency limits

### Risk 2: Large Accounts (Thousands of Resources)
**Mitigation:**
- Add progress indicators during collection
- Stream resources to disk if memory becomes an issue
- Consider pagination limits

### Risk 3: Resource Policy Complexity
**Mitigation:**
- Start with simple cases (Allow statements only)
- Add Deny statement support in v2
- Clearly document condition evaluation limitations

### Risk 4: Breaking Changes to Output Format
**Mitigation:**
- Keep text output exactly the same as default
- JSON is new opt-in feature
- Version JSON schema for future compatibility

## Documentation Updates

### README.md
- Add examples showing `--format json` usage
- Update "What it collects" section to include resource policies
- Add examples of report command output

### CLAUDE.md
- Update "Current Coverage" section
- Add resource policy collection to completed features
- Update testing scenarios

### ROADMAP.md
- Move completed features from "High Priority" to "Completed"
- Add version tags (v0.2.0)

## Success Metrics

After implementation:
- ✅ All commands support `--format json`
- ✅ JSON output is valid and programmatically parseable
- ✅ Resource policies collected from 5 AWS services
- ✅ Public access detection works
- ✅ Report command identifies at least 5 high-risk patterns
- ✅ Test coverage remains >90%
- ✅ All features documented with examples
