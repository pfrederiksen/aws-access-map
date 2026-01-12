# Social Media Posts for v0.1.0 Release

## Reddit - r/aws

**Title:** [Tool] aws-access-map v0.1.0 - CLI tool to instantly answer "who can access what?" in your AWS account

**Body:**
```
Hey r/aws! I built a CLI tool to solve a problem I kept hitting: figuring out who has access to AWS resources.

## The Problem

It's 2am. A contractor's last day is tomorrow. You need to know **right now**:
- "Who has admin access?"
- "Can this Lambda role access our production database?"
- "Which users can read secrets?"

The AWS Console IAM Policy Simulator is clunky. Writing jq pipelines gets old. Commercial tools are expensive and UI-first.

## The Solution

**aws-access-map** - Open source CLI that builds a graph of your permissions and answers questions in ~3 seconds.

```bash
# Find who has god-mode access
aws-access-map who-can "*" --action "*"

# Check if a role can access a resource
aws-access-map path \
  --from arn:aws:iam::ACCOUNT:role/Lambda \
  --to arn:aws:rds:...:db/prod \
  --action rds:Connect
```

## Features (v0.1.0)

✅ Fast IAM data collection (~2-3 seconds)
✅ Full wildcard matching (*, s3:Get*, iam:*User*)
✅ Query who can access any resource/action
✅ Find access paths between principals and resources
✅ 90%+ test coverage
✅ **100% free** - no AWS charges (IAM APIs are free)
✅ Local & private - no data sent anywhere

## Current Limitations (MVP)

⚠️ Identity-based policies only (no S3 bucket policies yet)
⚠️ Conditions not evaluated
⚠️ Single account only
⚠️ No role assumption chains

**Roadmap:** Resource policies, transitive access, JSON output, SCPs

## Installation

Pre-built binaries for macOS, Linux, Windows: https://github.com/pfrederiksen/aws-access-map/releases/tag/v0.1.0

Or via Go:
```bash
go install github.com/pfrederiksen/aws-access-map/cmd/aws-access-map@v0.1.0
```

## Repo

https://github.com/pfrederiksen/aws-access-map

Would love feedback, feature requests, or PRs! What AWS access questions do you need answered?
```

---

## Reddit - r/golang

**Title:** [Project] aws-access-map - Built a CLI tool in Go to map AWS IAM permissions

**Body:**
```
Hey r/golang! Sharing a project I just released v0.1.0 of - a CLI tool for AWS IAM access analysis.

## What it does

Builds an in-memory graph of AWS IAM permissions and answers queries like "who can access this resource?"

```bash
aws-access-map who-can "arn:aws:s3:::bucket/*" --action "s3:GetObject"
# Returns: alice (user), lambda-role (role)
```

## Why Go?

- Single binary distribution (no dependencies)
- Fast execution (<100ms queries on in-memory graph)
- AWS SDK v2 is excellent
- Cobra CLI framework made it easy
- Good concurrency primitives for AWS API calls

## Architecture

```
cmd/aws-access-map/     # CLI with cobra
internal/
  ├── collector/        # AWS SDK data fetching
  ├── graph/           # In-memory graph with sync.RWMutex
  ├── policy/          # IAM policy parser with gobwas/glob
  └── query/           # BFS traversal for path finding
```

## What I learned

- Graph modeling for permissions (nodes = principals/resources, edges = permissions)
- Pattern matching for AWS wildcards (s3:Get*, iam:*User*)
- Testing complex business logic (90%+ coverage with table-driven tests)
- Dealing with AWS's quirks (URL-encoded policies, JSON field names)

## Stats

- 50 comprehensive tests
- 95%+ coverage on core packages
- ~13MB binary (could be smaller with build flags)
- Tested against real AWS account

## Repo

https://github.com/pfrederiksen/aws-access-map

Happy to answer questions about implementation! Feedback on Go idioms welcome.
```

---

## Hacker News

**Title:** Show HN: aws-access-map – CLI to instantly query AWS IAM access ("who can reach this?")

**URL:** https://github.com/pfrederiksen/aws-access-map

**Comment (if needed):**
```
Author here. Built this to solve a recurring pain point: quickly answering "who has access to X?" in AWS.

The AWS Console IAM Policy Simulator is slow and clunky. Writing jq pipelines to parse policies gets old. Commercial tools are expensive and overkill for quick checks.

aws-access-map collects IAM data once (~3 seconds), builds a graph, then answers queries instantly:

    aws-access-map who-can "*" --action "*"  # Find admins
    aws-access-map who-can "arn:aws:s3:::my-bucket/*" --action "s3:GetObject"

Current version (v0.1.0) is an MVP that handles identity-based policies. Roadmap includes resource policies (S3, KMS), role assumption chains, and condition evaluation.

Tech stack: Go, in-memory graph with sync.RWMutex, gobwas/glob for AWS wildcards, 90%+ test coverage.

Free, open source (MIT), runs locally (no data sent anywhere), no AWS charges (IAM APIs are free).

Would love feedback on features or use cases I'm missing!
```

---

## Twitter/X (Short Version)

```
🚀 Just released aws-access-map v0.1.0!

Open-source CLI to instantly answer "who can access what?" in your AWS account.

✅ 100% free (no AWS charges)
✅ Fast queries (~3 seconds)
✅ Local & private
✅ Full wildcard support

Try it: https://github.com/pfrederiksen/aws-access-map

#AWS #DevOps #CloudSecurity #OpenSource
```

---

## LinkedIn (Professional Version)

```
Excited to release aws-access-map v0.1.0! 🎉

A free, open-source CLI tool that solves a common AWS challenge: quickly understanding "who can access what?"

**The Problem:**
Security audits, offboarding reviews, and permission debugging often require manual policy analysis or expensive commercial tools.

**The Solution:**
aws-access-map builds a permission graph of your AWS IAM policies and answers questions instantly:
• "Who has admin access?"
• "Can this role access our production database?"
• "Which users can read secrets?"

**Key Features:**
✅ Fast collection & query (~3 seconds)
✅ Full AWS wildcard pattern support
✅ 90%+ test coverage
✅ 100% free - no AWS API charges
✅ Local execution - your data stays private

Built in Go with comprehensive documentation and real-world testing.

Perfect for:
🔐 Security teams conducting audits
🛠️ DevOps engineers debugging permissions
📋 Compliance officers generating reports
⚙️ Platform teams validating IAM in CI/CD

Try it out: https://github.com/pfrederiksen/aws-access-map

I'd love to hear your feedback or use cases!

#AWS #CloudSecurity #DevOps #OpenSource #IAM
```
