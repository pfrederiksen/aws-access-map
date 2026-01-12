# Documentation Summary

This project has comprehensive documentation organized by audience and purpose.

## For Users

### [README.md](README.md) - Start Here! 📖
**Purpose:** Main documentation for users of aws-access-map

**Read this if:** You want to understand what aws-access-map does and why it's useful.

### [EXAMPLES.md](EXAMPLES.md) - Copy-Paste Examples 📋
**Purpose:** Quick reference with runnable examples

**Contains:**
- First-time setup
- Security audit examples (find admins, check permissions)
- Debugging examples (Lambda can't access S3, KMS issues)
- Compliance queries (export data, find inline policies)
- Incident response (exposed key, cross-account access)
- CI/CD integration examples
- Offboarding verification
- Multi-profile support
- Advanced jq queries
- Troubleshooting tips

**Read this if:** You want to copy-paste commands and start using the tool immediately.

### [COST.md](COST.md) - Cost Breakdown 💰
**Purpose:** Detailed analysis of costs to run the tool

**Contains:**
- Software licensing (MIT - free)
- AWS API call costs (IAM is free, S3/KMS negligible)
- Cost examples for different account sizes
- Comparison with commercial tools ($500-5000/mo vs $0)
- FAQ about hidden costs (spoiler: there are none)

**Read this if:** You want to know if there are any charges for running this tool.

**TL;DR:** ✅ Completely free. IAM API calls have no charge in AWS.

### Back to [README.md](README.md) for full context

**README also contains:**
- Why this tool exists (real-world scenarios)
- Installation instructions
- Quick start guide
- Real-world use cases with examples:
  - Security audits (who has admin access?)
  - Offboarding verification
  - Permission debugging
  - Compliance checks
  - Incident response
- Command reference with examples
- How it works (architecture overview)
- Current status and limitations
- Comparison with alternatives
- FAQ

**Read this if:** You want to use aws-access-map to solve AWS permission questions.

## For Contributors

### [CONTRIBUTING.md](CONTRIBUTING.md) - How to Help 🤝
**Purpose:** Guide for contributing code, docs, or bug reports

**Contains:**
- Ways to contribute (bugs, features, docs, code)
- Development setup instructions
- Project structure overview
- Coding guidelines and Git workflow
- Example: Adding S3 bucket policy support (full walkthrough)
- Testing approach

**Read this if:** You want to contribute to the project.

### [CLAUDE.md](CLAUDE.md) - Architecture Deep Dive 🏗️
**Purpose:** Detailed architecture and design decisions for developers

**Contains:**
- Project vision and target users
- Architecture decisions (why Go, why graph model)
- Core component breakdown:
  - Collector (AWS API integration)
  - Graph builder (policy parsing)
  - Query engine (traversal algorithms)
  - Policy parser (wildcards, conditions)
- Development patterns and best practices
- Key challenges and solutions
- Testing scenarios (unit, integration, real data)
- Real-world testing insights
- Implementation priorities (4-phase roadmap)
- Common implementation questions
- Example development session

**Read this if:** You're implementing new features or need to understand design decisions.

## For Testers

### [TESTING.md](TESTING.md) - Test Results & Known Issues 🧪
**Purpose:** Real-world testing results and current limitations

**Contains:**
- Test run results (what works, what doesn't)
- Data collection verification
- Known limitations with workarounds:
  - Wildcard matching (simplified)
  - Condition evaluation (not implemented)
  - Resource policies (not yet collected)
  - Transitive access (coming soon)
- Issues fixed during testing
- Next steps for production readiness
- Performance metrics
- Verification commands

**Read this if:** You want to know what's tested, what works, and what needs work.

## Documentation Flow

```
New User Flow:
README.md → EXAMPLES.md (copy-paste) → Try it out → TESTING.md (check limitations)

Quick Start Flow:
EXAMPLES.md → Copy command → Run → Success!

Contributor Flow:
README.md → CONTRIBUTING.md → CLAUDE.md → EXAMPLES.md (see what works) → Start coding

Deep Dive Flow:
README.md → CLAUDE.md → TESTING.md → EXAMPLES.md → Source code
```

## Quick Reference

| Question | Document |
|----------|----------|
| How do I install it? | README.md |
| Show me quick examples | EXAMPLES.md |
| Why should I use this? | README.md (Why This Exists) |
| How do I find admins? | EXAMPLES.md (Security Audits) or README.md (Use Cases) |
| How do I debug Lambda permissions? | EXAMPLES.md (Debugging) |
| Can it handle S3 policies? | README.md (Current Status) or TESTING.md |
| How do I contribute? | CONTRIBUTING.md |
| Why use a graph model? | CLAUDE.md (Architecture Decisions) |
| What's the roadmap? | README.md (Roadmap) or CLAUDE.md (Implementation Priorities) |
| What doesn't work yet? | README.md (Limitations) or TESTING.md |
| How do I add S3 support? | CONTRIBUTING.md (Example) or CLAUDE.md (Example Session) |
| CI/CD integration examples? | EXAMPLES.md (CI/CD Integration) |
| Incident response playbook? | EXAMPLES.md (Incident Response) |

## Keeping Docs Updated

When making changes, update:

- **New feature**: README.md (commands), CLAUDE.md (implementation notes), CONTRIBUTING.md (example if major)
- **Bug fix**: TESTING.md (remove from known issues)
- **Architecture change**: CLAUDE.md (design decisions)
- **New limitation discovered**: README.md (Current Status), TESTING.md (Known Issues)
- **Roadmap shift**: README.md (Roadmap), CLAUDE.md (Implementation Priorities)

## Philosophy

**README.md** answers: "What is this? Why should I care? How do I use it?"
**CONTRIBUTING.md** answers: "How do I help?"
**CLAUDE.md** answers: "How does it work? Why was it built this way?"
**TESTING.md** answers: "Does it work? What are the limitations?"

All docs use real-world examples and concrete scenarios. No hand-waving.
