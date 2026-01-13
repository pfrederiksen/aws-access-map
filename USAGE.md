# Usage Guide

Complete command reference for aws-access-map.

## Table of Contents

- [collect](#collect) - Fetch IAM data
- [who-can](#who-can) - Find principals with access
- [path](#path) - Discover access paths
- [report](#report) - Security analysis
- [simulate](#simulate) - Test policies locally (v0.7.0)
- [cache](#cache) - Manage cached data
- [Global Flags](#global-flags)
- [Condition Evaluation](#condition-evaluation)
- [Output Formats](#output-formats)

---

## collect

Fetch IAM and resource policy data from your AWS account (or entire organization).

### Syntax

```bash
aws-access-map collect [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--output`, `-o` | string | `aws-access-data.json` | Output file path |
| `--include-scps` | bool | `false` | Collect Service Control Policies (requires Organizations access) |
| `--all-accounts` | bool | `false` | Collect from all accounts in organization |
| `--role-name` | string | `OrganizationAccountAccessRole` | Role to assume in member accounts (with `--all-accounts`) |
| `--incremental` | bool | `false` | Use incremental caching (10x faster for large accounts) |
| `--cache` | bool | `false` | Force use cached data (fail if missing/stale) |
| `--no-cache` | bool | `false` | Force fresh collection, bypass cache |
| `--cache-ttl` | duration | `24h` | Cache time-to-live (e.g., `12h`, `30m`, `2h30m`) |

### Single Account Collection

```bash
# Basic collection (uses cache if available)
aws-access-map collect

# Force fresh collection
aws-access-map collect --no-cache

# Custom output file
aws-access-map collect --output prod-account.json

# Include SCPs from Organizations
aws-access-map collect --include-scps

# Incremental collection (10x faster for large accounts)
aws-access-map collect --incremental
```

### Multi-Account Collection

Collect from all accounts in your AWS Organization:

```bash
# Collect from all accounts
aws-access-map collect --all-accounts

# Use custom cross-account role
aws-access-map collect --all-accounts --role-name CustomAuditRole

# Multi-account with SCPs (auto-enabled)
aws-access-map collect --all-accounts
```

**Requirements:**
- Must run from AWS Organizations management account
- Cross-account role must exist in all member accounts
- Default role: `OrganizationAccountAccessRole` (created by AWS Organizations)
- See [PERMISSIONS.md](PERMISSIONS.md) for required permissions

**Output:**
- Per-account collection results (principals, resources, policies)
- Organization-wide SCPs (automatically collected)
- OU hierarchy for each account
- Success/failure counts and error details

### Caching Behavior

**Default** (no flags):
- Tries cache first
- Falls back to fresh collection if cache is stale/missing
- Saves fresh data to cache automatically

**`--cache`** (force cached):
- Requires valid cache
- Fails if cache is missing or stale
- Never performs fresh collection

**`--no-cache`** (force fresh):
- Always performs fresh collection
- Ignores existing cache
- Saves new data to cache

**Cache location:** `~/.aws-access-map/cache/{accountID}-{timestamp}.json`

### What It Collects

**IAM Entities:**
- ✅ IAM users (inline + managed policies)
- ✅ IAM roles (trust policies + permissions)
- ✅ IAM groups with membership resolution (v0.7.0)
- ✅ Permission boundaries
- ✅ Service Control Policies (with `--include-scps`)

**Resource Policies:**
- ✅ S3 bucket policies
- ✅ KMS key policies
- ✅ SQS queue policies
- ✅ SNS topic policies
- ✅ Secrets Manager resource policies
- ✅ Lambda functions (v0.7.0)
- ✅ API Gateway REST APIs (v0.7.0)
- ✅ ECR repositories (v0.7.0)
- ✅ EventBridge event buses (v0.7.0)

**Multi-Account:**
- ✅ Organization-wide collection (with `--all-accounts`)

---

## who-can

Find all principals (users, roles) that can perform an action on a resource.

### Syntax

```bash
aws-access-map who-can RESOURCE --action ACTION [OPTIONS]
```

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `RESOURCE` | Resource ARN or wildcard | `*`, `arn:aws:s3:::bucket/*` |
| `--action` | AWS action to check | `*`, `s3:GetObject`, `iam:CreateUser` |

### Options

| Flag | Type | Description |
|------|------|-------------|
| `--source-ip` | string | Source IP for condition evaluation (e.g., `203.0.113.50`) |
| `--mfa` | bool | Assume MFA is authenticated |
| `--org-id` | string | Principal organization ID (e.g., `o-123456`) |
| `--principal-arn` | string | Principal ARN for condition evaluation |

### Examples

```bash
# Find who has admin access
aws-access-map who-can "*" --action "*"

# Find who can read S3 bucket
aws-access-map who-can "arn:aws:s3:::my-bucket/*" --action "s3:GetObject"

# Find who can decrypt KMS key
aws-access-map who-can "arn:aws:kms:us-east-1:*:key/*" --action "kms:Decrypt"

# Find who can delete IAM users
aws-access-map who-can "arn:aws:iam::*:user/*" --action "iam:DeleteUser"

# With wildcard actions
aws-access-map who-can "arn:aws:s3:::*" --action "s3:*"
aws-access-map who-can "*" --action "s3:Get*"
```

### With Conditions

```bash
# IP-restricted access
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50"

# MFA-protected access
aws-access-map who-can "arn:aws:iam::*:*" --action "iam:*" \
  --mfa

# Organization-restricted access
aws-access-map who-can "arn:aws:s3:::shared-bucket/*" --action "s3:*" \
  --org-id "o-123456"

# Combined conditions
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50" \
  --mfa \
  --org-id "o-123456"
```

### Output

**Text format** (default):
```
Found 2 principal(s) with access:
  alice (user)
    ARN: arn:aws:iam::123456789012:user/alice
  AdminRole (role)
    ARN: arn:aws:iam::123456789012:role/AdminRole
```

**JSON format** (`--format json`):
```json
{
  "principals": [
    {
      "name": "alice",
      "type": "user",
      "arn": "arn:aws:iam::123456789012:user/alice"
    }
  ],
  "resource": "*",
  "action": "*"
}
```

---

## path

Discover access paths from a principal to a resource, including role assumption chains.

### Syntax

```bash
aws-access-map path --from PRINCIPAL --to RESOURCE --action ACTION [OPTIONS]
```

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--from` | Source principal ARN | `arn:aws:iam::123456789012:role/Lambda` |
| `--to` | Target resource ARN | `arn:aws:s3:::bucket/*` |
| `--action` | AWS action to check | `s3:GetObject` |

### Examples

```bash
# Direct access path
aws-access-map path \
  --from arn:aws:iam::123456789012:role/MyLambda \
  --to arn:aws:s3:::my-bucket/* \
  --action s3:GetObject

# Role assumption chain
aws-access-map path \
  --from arn:aws:iam::123456789012:user/alice \
  --to arn:aws:rds:us-east-1:123456789012:db:prod \
  --action rds:Connect

# Cross-account access
aws-access-map path \
  --from arn:aws:iam::111111111111:role/AppRole \
  --to arn:aws:s3:::bucket-in-222222222222/* \
  --action s3:GetObject
```

### Path Discovery Features

- **Direct access**: Principal → Resource (1 hop)
- **Role chains**: Principal → Role1 → Role2 → Resource (multi-hop)
- **BFS traversal**: Finds shortest paths first
- **Cycle detection**: Prevents infinite loops
- **Max depth**: Default 5 hops (configurable)
- **Multiple paths**: Returns up to 10 distinct paths

### Output

**Text format** (default):
```
Found 2 path(s):

Path 1 (2 hops):
  alice (user) →
  DevRole (role) →
  s3:GetObject on arn:aws:s3:::bucket/*

Path 2 (3 hops):
  alice (user) →
  DevRole (role) →
  ProdRole (role) →
  s3:GetObject on arn:aws:s3:::bucket/*
```

**JSON format** (`--format json`):
```json
{
  "paths": [
    {
      "hops": 2,
      "principals": ["alice", "DevRole"],
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::bucket/*"
    }
  ]
}
```

---

## report

Generate security reports highlighting high-risk access patterns.

### Syntax

```bash
aws-access-map report [OPTIONS]
```

### Options

| Flag | Type | Description |
|------|------|-------------|
| `--account` | string | AWS account ID to report on |
| `--high-risk` | bool | Only show high-risk findings |

### Examples

```bash
# All findings
aws-access-map report

# High-risk only
aws-access-map report --high-risk

# Specific account
aws-access-map report --account 123456789012

# JSON output for CI/CD
aws-access-map report --format json
```

### Risk Patterns Detected

| Pattern | Severity | Description |
|---------|----------|-------------|
| **Admin Access** | CRITICAL | Principals with `Action: *, Resource: *` |
| **Public Access** | CRITICAL/HIGH | Resources accessible by `Principal: *` |
| **Cross-Account** | MEDIUM | Principals from external AWS accounts |
| **Overly Permissive S3** | HIGH | Principals with `s3:*` on all buckets |
| **Sensitive Actions** | HIGH | Access to IAM/KMS/Secrets/STS on all resources |

### Output

**Text format** (default):
```
High-Risk Findings:

[CRITICAL] Admin Access
  alice (user)
    ARN: arn:aws:iam::123456789012:user/alice
    Policy: AdministratorAccess

[HIGH] Overly Permissive S3
  BackupRole (role)
    ARN: arn:aws:iam::123456789012:role/BackupRole
    Action: s3:*
    Resource: *
```

---

## simulate

Test policies locally without AWS credentials. Load policies from JSON files and run access queries, comparisons, and security validations. Perfect for CI/CD integration and local development.

### Subcommands

- `simulate who-can` - Query local policy data
- `simulate diff` - Compare two policy sets
- `simulate test` - Test a single policy change
- `simulate validate` - Check for security issues

---

### `simulate who-can`

Run who-can queries using local policy data instead of AWS APIs.

#### Syntax

```bash
aws-access-map simulate who-can RESOURCE --action ACTION --data FILE [OPTIONS]
```

#### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `RESOURCE` | Resource ARN or wildcard | `*`, `arn:aws:s3:::bucket/*` |
| `--action` | AWS action to check | `*`, `s3:GetObject` |
| `--data` | Local policy data file (JSON) | `policies.json` |

#### Examples

```bash
# Find admins in local policy file
aws-access-map simulate who-can "*" --action "*" \
  --data local-policies.json

# Check Lambda invocation access
aws-access-map simulate who-can \
  "arn:aws:lambda:us-east-1:123456789012:function:my-fn" \
  --action lambda:InvokeFunction \
  --data test-policies.json

# With condition context
aws-access-map simulate who-can "*" --action "*" \
  --data policies.json \
  --source-ip "203.0.113.50" \
  --mfa
```

**Use cases:**
- Test policies before AWS deployment
- Local development without AWS credentials
- CI/CD policy validation
- Security audits of proposed changes

---

### `simulate diff`

Compare access between two policy sets to see what changes.

#### Syntax

```bash
aws-access-map simulate diff --before FILE --after FILE [OPTIONS]
```

#### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--before` | Policy data before changes | `current.json` |
| `--after` | Policy data after changes | `proposed.json` |

#### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--resource` | Resource ARN to check | `*` |
| `--action` | Action to check | `*` |

#### Examples

```bash
# Compare all access
aws-access-map simulate diff \
  --before prod-current.json \
  --after proposed-changes.json

# Check specific resource
aws-access-map simulate diff \
  --before current.json \
  --after proposed.json \
  --resource "arn:aws:s3:::sensitive-bucket/*" \
  --action "s3:DeleteObject"

# Compare with specific action
aws-access-map simulate diff \
  --before before.json \
  --after after.json \
  --action "iam:*"
```

#### Output

Shows three categories of changes:

- **✅ NEW ACCESS GRANTED**: Principals who gained access
- **❌ ACCESS REVOKED**: Principals who lost access
- **➡️ UNCHANGED ACCESS**: Principals with same access

**Example output:**
```
Access Diff for * (action: *)

✅ NEW ACCESS GRANTED (2 principals):
  + arn:aws:iam::123456789012:role/Developer
  + arn:aws:iam::123456789012:user/alice

❌ ACCESS REVOKED (1 principal):
  - arn:aws:iam::123456789012:role/OldRole

➡️ UNCHANGED ACCESS (3 principals)
```

**Use cases:**
- Impact analysis before deploying policy changes
- Review proposed IAM changes in pull requests
- Audit policy updates for security compliance
- Track access changes over time

---

### `simulate test`

Test a single policy change to see its impact.

#### Syntax

```bash
aws-access-map simulate test --data BASE_FILE --add-policy POLICY_FILE --principal ARN
```

#### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--data` | Base policy data file | `current.json` |
| `--add-policy` | Policy to add (JSON file) | `new-role-policy.json` |
| `--principal` | Principal ARN to modify | `arn:aws:iam::*:role/MyRole` |

#### Examples

```bash
# Test adding a new policy
aws-access-map simulate test \
  --data current-policies.json \
  --add-policy new-s3-access.json \
  --principal "arn:aws:iam::123456789012:role/AppRole"

# Test with output file
aws-access-map simulate test \
  --data prod.json \
  --add-policy proposed-policy.json \
  --principal "arn:aws:iam::123456789012:user/alice" \
  --output test-result.json
```

#### Output

Shows:
- Security warnings (if policy grants admin access, etc.)
- Access changes for the modified principal
- Recommendations

**Example output:**
```
🔍 Testing policy change...
Principal: arn:aws:iam::123456789012:role/MyRole
New Policy: new-role-policy.json

⚠️  WARNING: This policy grants S3 full access (s3:* on arn:aws:s3:::*)

Access Changes:
  + NEW: Can perform s3:* on arn:aws:s3:::*
  + NEW: Can perform s3:PutObject on arn:aws:s3:::bucket/*
```

---

### `simulate validate`

Check policies for security issues. Exits with code 1 if issues are found (useful for CI/CD).

#### Syntax

```bash
aws-access-map simulate validate --data FILE
```

#### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--data` | Policy data file to validate | `policies.json` |

#### Examples

```bash
# Validate policies
aws-access-map simulate validate --data proposed-policies.json

# In CI/CD pipeline (exits 1 if issues found)
if ! aws-access-map simulate validate --data policies.json; then
  echo "Security issues detected!"
  exit 1
fi
```

#### Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| **Full admin access** | CRITICAL | Principals with `Action: *`, `Resource: *` |
| **Public access** | CRITICAL | Resources allowing `Principal: *` |
| **Unused principals** | LOW | Principals with no policies |
| **Overly permissive** | MEDIUM | Broad wildcards (e.g., `s3:*` on `*`) |

#### Output

**No issues:**
```
✅ No security issues detected
```

**Issues found (exit code 1):**
```
Security Issues Found:
⚠️  3 principals have full admin access
⚠️  2 resources allow public access

Details:
  Admin Access:
    - arn:aws:iam::123456789012:user/alice
    - arn:aws:iam::123456789012:role/AdminRole
```

**Use cases:**
- CI/CD policy validation gates
- Pre-deployment security checks
- Automated security audits
- Policy linting in development

---

### Policy File Format

All `simulate` commands use JSON files containing `CollectionResult` data:

```json
{
  "AccountID": "123456789012",
  "CollectedAt": "2025-01-13T10:00:00Z",
  "Principals": [
    {
      "ARN": "arn:aws:iam::123456789012:user/alice",
      "Type": "user",
      "Name": "alice",
      "Policies": [...]
    }
  ],
  "Resources": [
    {
      "ARN": "arn:aws:s3:::my-bucket",
      "Type": "s3",
      "ResourcePolicy": {...}
    }
  ]
}
```

**Generate policy files:**
```bash
# From AWS
aws-access-map collect -o policies.json

# For testing, create manually or modify existing files
```

---

### CI/CD Integration Example

```yaml
# .github/workflows/iam-validation.yml
name: Validate IAM Policy Changes

on:
  pull_request:
    paths:
      - 'iam-policies/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Download aws-access-map
        run: |
          curl -L https://github.com/pfrederiksen/aws-access-map/releases/latest/download/aws-access-map-linux-amd64 -o aws-access-map
          chmod +x aws-access-map

      - name: Collect current prod policies
        run: ./aws-access-map collect -o prod-current.json
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

      - name: Simulate proposed changes
        run: |
          ./aws-access-map simulate diff \
            --before prod-current.json \
            --after iam-policies/proposed.json \
            --action "*" > diff-output.txt
          cat diff-output.txt >> $GITHUB_STEP_SUMMARY

      - name: Validate security
        run: ./aws-access-map simulate validate --data iam-policies/proposed.json
```

---

## cache

Manage cached AWS collection data.

### Subcommands

#### `cache info`

View cache information for an account.

```bash
aws-access-map cache info --account 123456789012
```

**Output:**
```
Cache for account 123456789012:
  Location: /Users/you/.aws-access-map/cache/123456789012-20250113-143025.json
  Modified: 2025-01-13T14:30:25Z (2h5m ago)
  Status: VALID (TTL: 21h55m remaining)
```

#### `cache clear`

Delete cached data.

```bash
# Clear specific account
aws-access-map cache clear --account 123456789012

# Clear all cache
aws-access-map cache clear
```

---

## Global Flags

These flags work with all commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | (default) | AWS profile to use |
| `--region` | string | (profile region) | AWS region |
| `--format` | string | `text` | Output format (`text` or `json`) |
| `--debug` | bool | `false` | Enable debug logging |

### Examples

```bash
# Use specific AWS profile
aws-access-map collect --profile prod

# Use specific region
aws-access-map collect --region us-west-2

# JSON output
aws-access-map who-can "*" --action "*" --format json

# Debug mode
aws-access-map collect --debug
```

---

## Condition Evaluation

AWS policies often include conditions that must be met for access. aws-access-map supports 22 condition operators.

### Supported Operators

**String Operators:**
- `StringEquals`, `StringNotEquals`
- `StringLike`, `StringNotLike` (supports `*` wildcard)

**Boolean Operators:**
- `Bool` (e.g., `aws:MultiFactorAuthPresent`, `aws:SecureTransport`)

**IP Address Operators:**
- `IpAddress`, `NotIpAddress` (supports CIDR: `203.0.113.0/24`)

**Numeric Operators:**
- `NumericEquals`, `NumericNotEquals`
- `NumericLessThan`, `NumericLessThanEquals`
- `NumericGreaterThan`, `NumericGreaterThanEquals`

**Date Operators:**
- `DateEquals`, `DateNotEquals`
- `DateLessThan`, `DateLessThanEquals`
- `DateGreaterThan`, `DateGreaterThanEquals`

**ARN Operators:**
- `ArnEquals`, `ArnNotEquals`
- `ArnLike`, `ArnNotLike` (supports wildcards)

### Condition Context Flags

| Flag | Evaluates | Example Value |
|------|-----------|---------------|
| `--source-ip` | `IpAddress`, `NotIpAddress` | `203.0.113.50` |
| `--mfa` | `aws:MultiFactorAuthPresent` | (boolean flag) |
| `--org-id` | `aws:PrincipalOrgID` | `o-123456` |
| `--principal-arn` | `ArnEquals`, `ArnLike` | `arn:aws:iam::*:role/*` |

### Example Policy

```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "203.0.113.0/24"
    },
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

**Query with matching context:**
```bash
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50" \
  --mfa
```

---

## Output Formats

### Text Format (Default)

Human-readable, ideal for terminal use.

```bash
aws-access-map who-can "*" --action "*"
```

### JSON Format

Machine-readable, ideal for scripting and CI/CD.

```bash
aws-access-map who-can "*" --action "*" --format json
```

**Example JSON output:**
```json
{
  "principals": [
    {
      "name": "alice",
      "type": "user",
      "arn": "arn:aws:iam::123456789012:user/alice",
      "accountId": "123456789012"
    }
  ],
  "resource": "*",
  "action": "*",
  "evaluationContext": {
    "sourceIp": "203.0.113.50",
    "mfaAuthenticated": true
  }
}
```

### Piping to jq

```bash
# Extract just ARNs
aws-access-map who-can "*" --action "*" --format json | \
  jq -r '.principals[].arn'

# Count principals
aws-access-map who-can "arn:aws:s3:::*" --action "s3:*" --format json | \
  jq '.principals | length'

# Filter by type
aws-access-map who-can "*" --action "*" --format json | \
  jq '.principals[] | select(.type == "role")'
```

---

## Tips & Best Practices

### Performance

1. **Use caching** - Default behavior uses cache automatically
2. **Incremental mode** - Use `--incremental` for 10x speedup on large accounts (v0.7.0)
3. **Collect once, query many** - Collection is slow (~2-3s), queries are fast (<100ms)
4. **Multi-account** - Collection is parallelized across accounts
5. **Local simulation** - Use `simulate` commands to test without AWS API calls

### Security

1. **Least privilege** - See [PERMISSIONS.md](PERMISSIONS.md) for minimal required permissions
2. **Read-only** - aws-access-map never modifies your AWS account
3. **Local cache** - All data stored locally, never sent externally

### Debugging

1. **Use `--debug`** - Verbose output shows API calls and policy evaluation
2. **Check cache** - Use `cache info` to verify cache freshness
3. **Test conditions** - Use condition flags to test policy behavior

### CI/CD Integration

```bash
# Example: Detect admin users in CI
#!/bin/bash
set -e

# Collect data
aws-access-map collect --no-cache

# Find admins (JSON output)
admins=$(aws-access-map who-can "*" --action "*" --format json)

# Check count
count=$(echo "$admins" | jq '.principals | length')

if [ "$count" -gt 1 ]; then
  echo "ERROR: Found $count admin principals (expected 1)"
  echo "$admins" | jq '.principals[].name'
  exit 1
fi

echo "✅ Access control validated"
```

---

For real-world usage scenarios, see [EXAMPLES.md](EXAMPLES.md).

For IAM permission requirements, see [PERMISSIONS.md](PERMISSIONS.md).
