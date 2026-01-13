# aws-access-map

**Instant "who can reach this?" mapping for AWS resources.**

One command. One answer. No UI required.

✅ **100% free** • ⚡ **3 second queries** • 🔒 **Local & private** • 📖 **Open source**

---

📚 **Documentation**: [README](README.md) · [Examples](EXAMPLES.md) · [Permissions](PERMISSIONS.md) · [Contributing](CONTRIBUTING.md) · [Architecture](CLAUDE.md) · [Testing](TESTING.md)

---

## Why This Exists

You're debugging a permissions issue at 2am. A contractor's last day is tomorrow. A security audit is due Friday. You need to know **right now**:

- "Who has admin access to our AWS account?"
- "Can this Lambda role access our production database?"
- "Did that developer's permissions get fully revoked?"
- "Which services can decrypt our KMS key?"

**The current options are painful:**
- AWS Console IAM Policy Simulator: Clunky UI, one-at-a-time checks, no role chains
- `aws iam` CLI commands: Need to write complex jq pipelines, manually parse policies
- Commercial tools: Heavyweight, expensive, UI-first, require agents/scanning
- Manual review: Error-prone, time-consuming, miss transitive access

**aws-access-map solves this:** CLI-first, fast, open-source, answers in seconds.

## What It Does

Builds a graph of your AWS permissions and answers questions like:

```bash
# Who has god-mode access?
aws-access-map who-can "*" --action "*"

# Can this role access the production database?
aws-access-map path --from arn:aws:iam::ACCOUNT:role/Lambda --to arn:aws:rds:...:db/prod --action rds:Connect

# Which users can read secrets?
aws-access-map who-can "arn:aws:secretsmanager:*:*:secret/prod/*" --action secretsmanager:GetSecretValue

# Security audit: find all admin users
aws-access-map report --high-risk
```

**Handles complex AWS permission model:**
- Identity-based policies (inline + managed)
- Resource policies (S3, KMS, SQS, SNS, Secrets Manager)
- Role trust policies and assumption chains
- ✅ Service Control Policies (SCPs) with OU hierarchy
- ✅ Permission boundaries (principal-level constraints)
- ✅ Session policies (temporary session constraints)
- ✅ Multi-account via AWS Organizations
- ✅ File-based caching for fast repeated queries
- Resource-based grants

## Installation

### From Source
```bash
git clone https://github.com/pfrederiksen/aws-access-map
cd aws-access-map
make build
./build/aws-access-map --help
```

### Pre-built Binaries
Download from [releases](https://github.com/pfrederiksen/aws-access-map/releases) (coming soon).

### Go Install
```bash
go install github.com/pfrederiksen/aws-access-map/cmd/aws-access-map@latest
```

## Quick Start

**Prerequisites:** AWS credentials configured (environment variables, `~/.aws/credentials`, or IAM role).

```bash
# 1. Collect IAM data from your AWS account (takes ~2-3 seconds)
aws-access-map collect --output my-account.json

# 2. Find who has admin access
aws-access-map who-can "*" --action "*"

# Example output:
# Found 1 principal(s) with access:
#   alice (user)
#     ARN: arn:aws:iam::123456789012:user/alice
```

## Real-World Use Cases

### Security Audit: Who Has Admin Access?

**Scenario:** Your security team needs to audit who has full AWS access.

```bash
aws-access-map who-can "*" --action "*"
```

**What it checks:**
- Users/roles with `AdministratorAccess` managed policy
- Custom policies with `"Action": "*", "Resource": "*"`
- Policies with broad wildcards

### Offboarding: Verify Access Revoked

**Scenario:** A contractor left. You removed their IAM user, but did they have any service roles?

```bash
# Check if any roles have trust policies allowing their account
aws-access-map collect
grep "contractor-account-id" aws-access-data.json
```

### Debugging: Why Can't Lambda Access S3?

**Scenario:** Your Lambda function is getting Access Denied on S3.

```bash
# Check if the Lambda role can access the bucket
aws-access-map path \
  --from arn:aws:iam::123456789012:role/MyLambdaRole \
  --to arn:aws:s3:::my-bucket/* \
  --action s3:GetObject

# If no path found, you know the permissions are missing
```

### Compliance: Find Overly Permissive Roles

**Scenario:** Security audit flagged potential over-privileged service accounts.

```bash
aws-access-map report --high-risk

# Look for:
# - Roles with Action: "*"
# - Cross-account trust relationships
# - Public access to resources
```

### Incident Response: Blast Radius Analysis

**Scenario:** A key was exposed. What can it access?

```bash
# If it's an IAM user access key
aws-access-map who-can "*" --action "*" | grep exposed-user

# Check what they can reach
aws-access-map collect
# Parse the collected data to see all their policies
```

### Condition-Based Access Control: IP Restrictions

**Scenario:** Your policies require office IP access. Verify if users can access from home.

```bash
# Check if admin can access from office IP (should work)
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50"

# Check if admin can access from home IP (should be blocked if IP-restricted)
aws-access-map who-can "*" --action "*" \
  --source-ip "192.0.2.1"
```

**Real policy example:**
```json
{
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "203.0.113.0/24"
    }
  }
}
```

### MFA-Protected Resources

**Scenario:** Sensitive operations require MFA. Verify MFA enforcement.

```bash
# Check if user can perform sensitive action without MFA (should be denied)
aws-access-map who-can "arn:aws:iam::*:*" --action "iam:DeleteUser"

# Check with MFA (should be allowed if policy requires MFA)
aws-access-map who-can "arn:aws:iam::*:*" --action "iam:DeleteUser" --mfa
```

**Real policy example:**
```json
{
  "Effect": "Allow",
  "Action": "iam:*",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

## Commands

### `collect`
Fetch IAM data from your AWS account (or entire organization) and save it locally.

```bash
aws-access-map collect [OPTIONS]

# Single Account Examples:
aws-access-map collect                              # Saves to aws-access-data.json (with auto-caching)
aws-access-map collect --output prod-account.json   # Custom filename
aws-access-map collect --profile prod               # Use specific AWS profile
aws-access-map collect --format json                # JSON output (machine-readable)
aws-access-map collect --include-scps               # Include Service Control Policies (requires Organizations access)

# Caching Options:
aws-access-map collect                              # Default: try cache first, collect if stale/missing
aws-access-map collect --no-cache                   # Force fresh collection, bypass cache
aws-access-map collect --cache                      # Force use cache, fail if missing/stale
aws-access-map collect --cache-ttl 12h              # Custom cache TTL (default: 24h)

# Multi-Account Collection (Organization-Wide):
aws-access-map collect --all-accounts               # Collect from all accounts in organization
aws-access-map collect --all-accounts --role-name CustomRole  # Use custom cross-account role
```

**What it collects:**
- ✅ IAM users (with inline and managed policies)
- ✅ IAM roles (with trust policies and permissions)
- ✅ **Permission boundaries** (principal-level constraints)
- ✅ S3 bucket policies
- ✅ KMS key policies
- ✅ SQS queue policies
- ✅ SNS topic policies
- ✅ Secrets Manager resource policies
- ✅ **Service Control Policies (SCPs)** with `--include-scps` flag (requires Organizations access)
- ✅ **Multi-account data** with `--all-accounts` flag (requires Organizations access and cross-account role)
- ⏳ IAM groups (roadmap)

**Service Control Policies (SCPs):**

SCPs are organization-level policies that set maximum permissions for accounts in AWS Organizations. When collected, aws-access-map automatically:

1. **Fetches SCP targets**: Determines which accounts/OUs each SCP is attached to
2. **Resolves OU hierarchy**: Traverses the organizational unit tree to determine which OUs your account belongs to
3. **Filters SCPs accurately**: Only applies SCPs that are attached to:
   - Your account directly
   - An OU that contains your account
   - The organization root (applies to all accounts)
4. **Evaluates SCPs first**: SCPs are checked BEFORE identity and resource policies (matching AWS behavior)

**Requirements for SCP collection:**
- Must run from AWS Organizations management account (or delegated admin)
- Requires Organizations read permissions (see [PERMISSIONS.md](PERMISSIONS.md))
- Gracefully skips SCPs if permissions unavailable

**Example:**
```bash
# From management account with Organizations access
aws-access-map collect --include-scps

# Output includes:
# "Collected 5 Service Control Policies (SCPs)"
#
# SCPs will be automatically applied during who-can and path queries
```

See [PERMISSIONS.md](PERMISSIONS.md) for detailed IAM permission requirements.

**Multi-Account Collection:**

Collect IAM data from all accounts in your AWS Organization in a single command:

```bash
# Collect from all accounts (requires Organizations access)
aws-access-map collect --all-accounts

# Use custom cross-account role name (default: OrganizationAccountAccessRole)
aws-access-map collect --all-accounts --role-name MyCustomRole
```

**How it works:**
1. Lists all active accounts in your AWS Organization
2. Assumes a role in each member account (via STS AssumeRole)
3. Collects IAM data from each account in parallel
4. Aggregates results with organization-wide SCPs
5. Tracks success/failure per account

**Requirements:**
- Must run from AWS Organizations management account (or delegated admin)
- Requires cross-account role with IAM read permissions in each member account
- Default role name: `OrganizationAccountAccessRole` (created automatically by AWS Organizations)
- See [PERMISSIONS.md](PERMISSIONS.md) for detailed permission requirements

**Output includes:**
- Per-account collection results (principals, resources, policies)
- Organization-wide SCPs with target information
- OU hierarchy for each account
- Success/failure counts and failed account IDs

**Performance:** Collection speed depends on number of accounts and IAM resources per account. Typical organization (10-50 accounts) completes in 30-60 seconds.

**Permission Boundaries and Session Policies:**

aws-access-map fully evaluates AWS's constraint mechanisms:

- **Permission Boundaries**: Principal-level filters that limit maximum permissions. Automatically collected with users/roles and enforced during queries.
- **Session Policies**: Temporary constraints applied during AssumeRole operations. Can be specified via `EvaluationContext` in code for programmatic use.

Both use an allowlist model: actions must be explicitly allowed, and explicit denies override allows. These constraints are evaluated in the correct order per [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html):

1. SCPs (organization-level)
2. Permission boundaries (principal-level)
3. Session policies (session-level)
4. Explicit denies (always win)
5. Explicit allows (grant access)
6. Implicit deny (default)

See [PERMISSIONS.md](PERMISSIONS.md) for detailed IAM permission requirements.

### `who-can`
Find all principals that can perform an action on a resource.

```bash
aws-access-map who-can RESOURCE --action ACTION [--profile PROFILE]

# Examples:
aws-access-map who-can "*" --action "*"                         # Find admins
aws-access-map who-can "arn:aws:s3:::my-bucket/*" --action "s3:GetObject"
aws-access-map who-can "arn:aws:kms:us-east-1:*:key/*" --action "kms:Decrypt"
```

**Current behavior:**
- ✅ Queries identity-based policies (IAM users/roles)
- ✅ Queries resource-based policies (S3, KMS, SQS, SNS, Secrets Manager)
- ✅ Full wildcard matching (supports `*`, `s3:Get*`, `iam:*User*`, etc.)
- ✅ JSON output format with `--format json` flag
- ✅ **Condition evaluation** with runtime context (IP, MFA, Org ID, dates, etc.)

**Condition Evaluation:**

AWS policies often include conditions that must be met for access to be granted. aws-access-map now supports evaluating these conditions with runtime context:

```bash
# Check if user can access from specific IP (evaluates IpAddress conditions)
aws-access-map who-can "arn:aws:s3:::bucket/*" --action "s3:GetObject" \
  --source-ip "203.0.113.50"

# Check access with MFA required (evaluates Bool conditions)
aws-access-map who-can "*" --action "*" --mfa

# Check cross-account access with org restriction (evaluates StringEquals conditions)
aws-access-map who-can "arn:aws:s3:::shared-bucket/*" --action "s3:*" \
  --org-id "o-123456"

# Check principal-specific conditions
aws-access-map who-can "arn:aws:s3:::bucket/*" --action "s3:GetObject" \
  --principal-arn "arn:aws:iam::123456789012:user/alice"

# Combine multiple conditions
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50" \
  --mfa \
  --org-id "o-123456"
```

**Supported condition operators (22 total):**
- **String**: StringEquals, StringNotEquals, StringLike (case-sensitive, `*` wildcard)
- **Boolean**: Bool (aws:MultiFactorAuthPresent, aws:SecureTransport)
- **IP Address**: IpAddress, NotIpAddress (CIDR blocks, e.g., `203.0.113.0/24`)
- **Numeric**: NumericEquals, NumericNotEquals, NumericLessThan, NumericLessThanEquals, NumericGreaterThan, NumericGreaterThanEquals
- **Date**: DateEquals, DateNotEquals, DateLessThan, DateLessThanEquals, DateGreaterThan, DateGreaterThanEquals
- **ARN**: ArnEquals, ArnNotEquals, ArnLike, ArnNotLike (ARN pattern matching)

**Condition flags:**
- `--source-ip IP`: Source IP for IpAddress conditions (e.g., `203.0.113.50`)
- `--mfa`: Assume MFA is authenticated (aws:MultiFactorAuthPresent = true)
- `--org-id ID`: Principal's organization ID (e.g., `o-123456`)
- `--principal-arn ARN`: Principal ARN for ArnEquals/ArnLike conditions

**Default behavior:** When condition flags are not provided, the tool uses permissive defaults (conditions pass by default). This maintains backward compatibility while allowing opt-in strict evaluation.

### `path`
Discover access paths from one principal to a resource.

```bash
aws-access-map path --from PRINCIPAL --to RESOURCE --action ACTION

# Examples:
aws-access-map path \
  --from arn:aws:iam::123456789012:role/MyLambda \
  --to arn:aws:s3:::sensitive-bucket/* \
  --action s3:GetObject
```

**Features:**
- ✅ Finds direct access paths
- ✅ Discovers role assumption chains (multi-hop paths)
- ✅ BFS traversal for shortest paths
- ✅ Cycle detection and max depth limiting (default: 5 hops)
- ✅ Finds multiple paths when they exist (up to 10 paths)
- ✅ JSON output format with `--format json` flag

**Example multi-hop path:**
```
User Alice → AssumeRole(DevRole) → AssumeRole(ProdRole) → s3:GetObject → bucket
```

### `report`
Generate security reports highlighting high-risk access patterns.

```bash
aws-access-map report [--account ACCOUNT_ID] [--high-risk] [--format FORMAT]

# Examples:
aws-access-map report                               # Show all findings
aws-access-map report --high-risk                   # Only high-risk findings
aws-access-map report --format json                 # JSON output for CI/CD
```

**Detects 5 high-risk patterns:**
- ✅ **Admin Access** (CRITICAL): Principals with unrestricted wildcard permissions (`Action: *, Resource: *`)
- ✅ **Public Access** (HIGH/CRITICAL): Resources accessible by anonymous users (Principal: `*`)
- ✅ **Cross-Account Access** (MEDIUM): Principals from external AWS accounts
- ✅ **Overly Permissive S3** (HIGH): Principals with `s3:*` on all buckets
- ✅ **Sensitive Actions** (HIGH): Access to IAM/KMS/Secrets Manager/STS on all resources

### `cache`
Manage cached AWS collection data for faster repeated queries.

```bash
# View cache information for an account
aws-access-map cache info --account 123456789012

# Clear cache for specific account
aws-access-map cache clear --account 123456789012

# Clear all cached data
aws-access-map cache clear
```

**Caching behavior:**
- **Automatic**: Data is automatically cached after collection (stored in `~/.aws-access-map/cache/`)
- **TTL**: Default 24-hour expiration (configurable with `--cache-ttl`)
- **Per-account**: Each account has its own cache file (`{accountID}-{timestamp}.json`)
- **Transparent**: Queries automatically use cache if available and fresh
- **Manual control**: Use `--cache`, `--no-cache`, or `--cache-ttl` flags

**Cache file location:** `~/.aws-access-map/cache/{accountID}-{timestamp}.json`

**When cache is used:**
- By default, `collect` checks cache first and falls back to fresh collection if stale/missing
- Use `--cache` to force using cache (fails if unavailable)
- Use `--no-cache` to force fresh collection
- `who-can`, `path`, and `report` commands automatically use cached data from most recent `collect`

## How It Works

```
┌─────────┐    ┌───────┐    ┌───────┐
│ Collect │ -> │ Graph │ -> │ Query │
└─────────┘    └───────┘    └───────┘
     │             │             │
  AWS APIs    In-memory    Traverse &
  (IAM, S3,    Structure     Answer
   KMS, etc)   (Nodes +
               Edges)
```

**1. Collect** - Fetches data via AWS SDK:
- IAM users, roles, groups
- Inline policies (attached directly)
- Managed policies (AWS or custom)
- Trust policies (who can assume roles)
- Resource policies (S3, KMS, etc.) - coming soon

**2. Build Graph** - Parses policies into a graph:
- **Nodes**: Principals (users, roles), Resources (S3 buckets, KMS keys), Actions
- **Edges**: Permissions (Principal → Action → Resource), Trust (Principal → Role)
- **Attributes**: Allow/Deny effect, conditions, policy type

**3. Query** - Traverses the graph to find answers:
- Direct access: "Does user X have permission Y?"
- Reverse lookup: "Who can perform action Y?"
- Path finding: "How can principal X reach resource Z?"
- Risk analysis: "What has public access?" (coming soon)

## Current Status

**✅ Working**
- Collect IAM users and roles from AWS
- Collect resource policies (S3, KMS, SQS, SNS, Secrets Manager)
- **Service Control Policies (SCPs)** with OU hierarchy tracking and accurate filtering
- Parse inline and managed policies
- Build in-memory permission graph with resource policies
- Query direct access (`who-can`, `path` commands)
- **Role assumption chain traversal** (multi-hop path finding with BFS)
- **Policy condition evaluation** with 22 operators (String, Bool, IP, Numeric, Date, ARN)
- Security audit reports with 5 high-risk pattern detections
- JSON output format for CI/CD automation
- Full wildcard matching (glob patterns: `*`, `s3:Get*`, `iam:*User*`)
- 90%+ test coverage with 100+ comprehensive tests

**⚠️  Limitations**
- Single account only (multi-account planned for future release)
- Some advanced condition operators not yet supported (IfExists variants, ForAllValues, ForAnyValue)

See [TESTING.md](TESTING.md) for detailed test results and known issues.

## Architecture

```
aws-access-map/
├── cmd/aws-access-map/     # CLI entry point
├── internal/
│   ├── collector/          # AWS API data collection
│   ├── graph/              # Graph data structure and storage
│   ├── query/              # Query engine and path finding
│   └── policy/             # Policy parsing and evaluation
├── pkg/types/              # Shared types and interfaces
└── testdata/               # Example policies and test data
```

**Key design decisions:**
- **Go** for single-binary distribution and fast execution
- **In-memory graph** for sub-second queries (good for single accounts)
- **Graph-based model** to handle transitive access naturally
- **CLI-first** design (APIs and UI come later)

See [CLAUDE.md](CLAUDE.md) for development guide and architecture deep dive.

## Comparison with Alternatives

| Feature | aws-access-map | AWS Console | `aws iam` CLI | Commercial Tools |
|---------|---------------|-------------|---------------|------------------|
| Speed | ⚡ Seconds | 🐌 Minutes | 🐢 Manual | ⏳ Requires setup |
| Cost | **$0** | $0 | $0 | **$500-5000/mo** |
| AWS API charges | **$0** | $0 | $0 | Varies |
| Installation | Binary | Browser | Built-in | Agents/SaaS |
| Role chains | ✅ | Limited | Manual | ✅ |
| Scripting | ✅ | ❌ | Complex | API |
| Offline | ✅ Cache | ❌ | ❌ | Varies |
| Open source | ✅ | ❌ | ✅ | ❌ |
| Privacy | Local only | AWS | Local | Varies |

**When to use aws-access-map:**
- Quick security audits
- Debugging permission issues
- CI/CD permission validation
- Scripted compliance checks

**When to use alternatives:**
- AWS Console: Visual policy editing, one-time checks
- Commercial tools: Enterprise features, compliance reporting, continuous monitoring
- `aws iam` CLI: Specific AWS operations, scripting AWS changes

## FAQ

**Q: Is this free? Are there AWS charges?**
A: ✅ **100% free.** The software is open source (MIT license) and IAM API calls have no charge in AWS. See [COST.md](COST.md) for detailed breakdown. When we add S3/KMS collection, costs are negligible (<$0.05 per run).

**Q: Does this require special permissions?**
A: It needs read-only IAM permissions (`iam:Get*`, `iam:List*`). For SCP collection, Organizations read permissions are required. See [PERMISSIONS.md](PERMISSIONS.md) for complete details. The tool is completely read-only and cannot modify your AWS resources.

**Q: Is my data sent anywhere?**
A: No. Everything runs locally on your machine. Data is only fetched from AWS and stored in a local JSON file. No telemetry, no cloud services, no third parties.

**Q: How often should I run `collect`?**
A: Depends on how frequently your IAM policies change. Daily for active accounts, weekly for stable ones. Each run is free, so run as often as you need.

**Q: Can I use this in CI/CD?**
A: Yes! Use `collect` then `who-can` to validate that new deployments don't grant unintended permissions. It's fast (3 seconds) and free to run on every build.

**Q: What AWS regions does it support?**
A: IAM is global, so region doesn't matter. The tool defaults to `us-east-1` for API calls. For resource policies (S3, KMS), you'll need to specify the region.

## Contributing

Contributions welcome! Here's how to help:

1. **Report bugs**: Open an issue with reproducible steps
2. **Request features**: Describe your use case and why it's needed
3. **Submit PRs**: Check [CLAUDE.md](CLAUDE.md) for architecture guidance
4. **Share examples**: Real-world use cases help prioritize features

**Good first issues:**
- Enhanced wildcard matching (glob patterns)
- Additional resource collectors (S3, KMS, SQS)
- Output formatting (JSON, CSV, table)
- Test coverage improvements

## License

MIT

## Acknowledgments

Inspired by the pain of debugging AWS permissions at 2am. Built because existing tools were too slow, too expensive, or too complicated.

Special thanks to the AWS IAM team for creating such a... comprehensive... permission model. 😅
