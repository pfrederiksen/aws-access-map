# Usage Guide

Complete command reference for aws-access-map.

## Table of Contents

- [collect](#collect) - Fetch IAM data
- [who-can](#who-can) - Find principals with access
- [path](#path) - Discover access paths
- [report](#report) - Security analysis
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

- ✅ IAM users (inline + managed policies)
- ✅ IAM roles (trust policies + permissions)
- ✅ Permission boundaries
- ✅ S3 bucket policies
- ✅ KMS key policies
- ✅ SQS queue policies
- ✅ SNS topic policies
- ✅ Secrets Manager resource policies
- ✅ Service Control Policies (with `--include-scps`)
- ✅ Multi-account data (with `--all-accounts`)

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
2. **Collect once, query many** - Collection is slow (~2-3s), queries are fast (<100ms)
3. **Multi-account** - Collection is parallelized across accounts

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
