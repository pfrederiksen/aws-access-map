# aws-access-map

**Instant "who can reach this?" mapping for AWS resources.**

One command. One answer. No UI required.

✅ **100% free** • ⚡ **3 second queries** • 🔒 **Local & private** • 📖 **Open source**

---

📚 **Documentation**: [Examples](EXAMPLES.md) · [Usage Guide](USAGE.md) · [Permissions](PERMISSIONS.md) · [Architecture](CLAUDE.md) · [Testing](TESTING.md)

---

## Why This Exists

You're debugging permissions at 2am. A contractor leaves tomorrow. Security audit Friday. You need to know **right now**:

- "Who has admin access to our AWS account?"
- "Can this Lambda role access our production database?"
- "Which services can decrypt our KMS key?"

**aws-access-map solves this:** CLI-first, fast, open-source. Answers in seconds.

## What It Does

```bash
# Who has god-mode access?
aws-access-map who-can "*" --action "*"

# Can this role access the database?
aws-access-map path \
  --from arn:aws:iam::ACCOUNT:role/Lambda \
  --to arn:aws:rds:...:db/prod \
  --action rds:Connect

# Collect from entire organization (multi-account)
aws-access-map collect --all-accounts
```

**Handles the full AWS IAM policy evaluation model:**
- ✅ Service Control Policies (SCPs) - organization-level
- ✅ Permission boundaries - principal-level constraints
- ✅ Session policies - temporary session constraints
- ✅ Identity & resource policies
- ✅ Condition evaluation (IP, MFA, dates, ARNs, etc.)
- ✅ Multi-account via AWS Organizations
- ✅ File-based caching (24h TTL)

## Installation

### From Source
```bash
git clone https://github.com/pfrederiksen/aws-access-map
cd aws-access-map
make build
./build/aws-access-map --help
```

### Go Install
```bash
go install github.com/pfrederiksen/aws-access-map/cmd/aws-access-map@latest
```

### Pre-built Binaries
Download from [releases](https://github.com/pfrederiksen/aws-access-map/releases) (coming soon).

## Quick Start

**Prerequisites:** AWS credentials configured (environment variables, `~/.aws/credentials`, or IAM role).

```bash
# 1. Collect IAM data from your AWS account
aws-access-map collect

# 2. Find who has admin access
aws-access-map who-can "*" --action "*"

# 3. Check if a role can access S3
aws-access-map path \
  --from arn:aws:iam::123456789012:role/MyRole \
  --to arn:aws:s3:::my-bucket/* \
  --action s3:GetObject
```

**See [EXAMPLES.md](EXAMPLES.md) for real-world scenarios** (offboarding, debugging, audits, incident response).

## Core Commands

### `collect` - Fetch IAM Data
```bash
# Single account with auto-caching
aws-access-map collect

# Organization-wide (all accounts)
aws-access-map collect --all-accounts

# Force fresh data (bypass cache)
aws-access-map collect --no-cache

# Include Service Control Policies
aws-access-map collect --include-scps
```

**Caching:** Data is automatically cached for 24 hours in `~/.aws-access-map/cache/`. Use `--cache` to force cache, `--no-cache` to bypass, or `--cache-ttl` to customize expiration.

### `who-can` - Find Principals with Access
```bash
# Find admins
aws-access-map who-can "*" --action "*"

# Find who can read S3 bucket
aws-access-map who-can "arn:aws:s3:::my-bucket/*" --action "s3:GetObject"

# With condition context (IP, MFA, etc.)
aws-access-map who-can "*" --action "*" \
  --source-ip "203.0.113.50" \
  --mfa
```

### `path` - Discover Access Paths
```bash
# Find how principal reaches resource
aws-access-map path \
  --from arn:aws:iam::123456789012:role/AppRole \
  --to arn:aws:s3:::sensitive-bucket/* \
  --action s3:GetObject
```

Discovers direct access and role assumption chains (up to 5 hops).

### `report` - Security Analysis
```bash
# Find high-risk access patterns
aws-access-map report --high-risk
```

Detects: admin access, public access, cross-account access, overly permissive roles, sensitive actions.

### `cache` - Manage Cached Data
```bash
# View cache info
aws-access-map cache info --account 123456789012

# Clear cache
aws-access-map cache clear
```

**See [USAGE.md](USAGE.md) for complete command reference.**

## Key Features

### ✅ Complete IAM Policy Evaluation

Implements AWS's 6-step evaluation logic in correct order:

1. **SCPs** - Organization-level denies (v0.5.0)
2. **Permission boundaries** - Principal-level allowlist (v0.6.0)
3. **Session policies** - Temporary session constraints (v0.6.0)
4. **Explicit denies** - Always win
5. **Explicit allows** - Grant access
6. **Implicit deny** - Default

### ✅ Multi-Account Support (v0.6.0)

```bash
# Collect from all accounts in organization
aws-access-map collect --all-accounts

# Use custom cross-account role
aws-access-map collect --all-accounts --role-name CustomAuditRole
```

**Requirements:**
- AWS Organizations access from management account
- Cross-account role in member accounts (default: `OrganizationAccountAccessRole`)
- See [PERMISSIONS.md](PERMISSIONS.md) for details

### ✅ Condition Evaluation (v0.4.0)

Supports 22 condition operators: `StringEquals`, `IpAddress`, `Bool`, `DateLessThan`, `NumericGreaterThan`, `ArnLike`, etc.

```bash
# Evaluate IP-restricted policies
aws-access-map who-can "*" --action "*" --source-ip "203.0.113.50"

# Check MFA-protected access
aws-access-map who-can "arn:aws:iam::*:*" --action "iam:*" --mfa
```

### ✅ Performance

- **Fast queries**: 50-100ms for typical accounts
- **Auto-caching**: 24h TTL (configurable)
- **Multi-account**: Parallel collection across accounts
- **No external dependencies**: Single binary, no database required

## What It Collects

- ✅ IAM users, roles, groups (inline + managed policies)
- ✅ Permission boundaries (v0.6.0)
- ✅ Service Control Policies (v0.5.0)
- ✅ S3, KMS, SQS, SNS, Secrets Manager resource policies
- ✅ Role trust policies and assumption chains
- ✅ Multi-account data via Organizations (v0.6.0)

See [PERMISSIONS.md](PERMISSIONS.md) for required IAM permissions.

## How It Works

```
┌─────────┐    ┌───────┐    ┌───────┐
│ Collect │ -> │ Graph │ -> │ Query │
└─────────┘    └───────┘    └───────┘
  AWS APIs    In-memory   BFS/Policy
  2-3 sec     < 1 sec      < 100ms
```

1. **Collect**: Fetches policies via AWS SDK, caches locally
2. **Graph**: Builds in-memory structure (principals → actions → resources)
3. **Query**: Traverses graph with BFS, evaluates constraints (SCPs, boundaries, sessions)

## Comparison

| Feature | aws-access-map | AWS IAM Policy Simulator | Commercial Tools |
|---------|----------------|--------------------------|------------------|
| **Speed** | 3 second queries | Manual, one-at-a-time | Minutes (scanning) |
| **Cost** | Free | Free | $$$$ |
| **Offline** | ✅ Yes (local cache) | ❌ No | ❌ No |
| **Multi-account** | ✅ Yes (v0.6.0) | ❌ No | ✅ Yes |
| **Role chains** | ✅ Yes (BFS) | ❌ No | ⚠️ Limited |
| **SCPs** | ✅ Yes (v0.5.0) | ✅ Yes | ✅ Yes |
| **Conditions** | ✅ Yes (22 operators) | ✅ Yes | ✅ Yes |
| **CLI-first** | ✅ Yes | ❌ UI-based | ❌ UI-based |

## Roadmap

- ✅ v0.1.0 - IAM collection & basic queries
- ✅ v0.2.0 - Resource policies (S3, KMS, SQS, SNS)
- ✅ v0.3.0 - Role assumption chains (BFS)
- ✅ v0.4.0 - Policy condition evaluation
- ✅ v0.5.0 - Service Control Policies (SCPs)
- ✅ v0.6.0 - Permission boundaries, session policies, caching, multi-account
- ⏳ v0.7.0 - IAM groups, resource tagging
- ⏳ v0.8.0 - Web UI (optional)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and architecture.

**Key areas for contribution:**
- Additional resource types (Lambda, API Gateway, etc.)
- More condition operators
- Performance optimizations
- Documentation improvements

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📖 [Documentation](https://github.com/pfrederiksen/aws-access-map)
- 🐛 [Issue Tracker](https://github.com/pfrederiksen/aws-access-map/issues)
- 💬 [Discussions](https://github.com/pfrederiksen/aws-access-map/discussions)

---

**Built with ❤️ for DevOps engineers debugging permissions at 3am.**
