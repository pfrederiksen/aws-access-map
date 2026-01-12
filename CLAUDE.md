# CLAUDE.md - Development Guide

This document contains architecture decisions, development patterns, and context for working on aws-access-map with Claude Code or other AI assistants.

## Project Vision

Build a fast, CLI-first tool that answers AWS access questions through graph traversal. The focus is on **speed and simplicity: one command, one answer**.

### Target Users

1. **DevOps Engineers** debugging permission issues at 3am
2. **Security Teams** auditing who has access to sensitive resources
3. **Compliance Officers** generating access reports
4. **Platform Teams** validating IAM policies in CI/CD

### Non-Goals (for now)

- ❌ Policy management/editing (read-only tool)
- ❌ Real-time monitoring (batch analysis)
- ❌ Web UI (CLI-first, UI later)
- ❌ Policy recommendations (detection only)

## Architecture Decisions

### Language: Go

**Why Go:**
- Single binary distribution (easy installation)
- Fast compilation and execution
- Excellent AWS SDK (aws-sdk-go-v2)
- Strong CLI library ecosystem (cobra, viper)
- Good for concurrent operations (collecting data from AWS)

### Core Components

#### 1. Collector (`internal/collector/`)
Fetches data from AWS APIs:
- IAM policies (identity-based, managed, inline)
- Resource policies (S3, KMS, SQS, SNS, Secrets Manager, etc.)
- Role trust policies
- Service Control Policies (SCPs)
- Permission boundaries
- KMS grants

**Design notes:**
- Use AWS SDK v2 with pagination
- Concurrent fetching where possible (multiple API calls in parallel)
- Cache results locally to avoid repeated API calls
- Support for multiple regions and accounts

#### 2. Graph Builder (`internal/graph/`)
Converts AWS policies into a graph structure:
- **Nodes**: Principals (users, roles, groups), Resources (S3 buckets, KMS keys, etc.), Actions
- **Edges**: Permissions (who can do what), Trust relationships (role assumptions)

**Graph schema:**
```
Principal -[CAN_PERFORM]-> Action -[ON]-> Resource
Principal -[CAN_ASSUME]-> Role (another Principal)
SCP -[DENIES]-> Action
```

**Storage options:**
- MVP: In-memory graph (fast for single account)
- Future: SQLite or DuckDB for persistence and large accounts

#### 3. Policy Parser (`internal/policy/`)
Parses AWS IAM policy documents into structured data:
- Extract principals, actions, resources, conditions, effects (Allow/Deny)
- Handle wildcards and pattern matching
- Policy condition evaluation (simplified for MVP)

**Key challenges:**
- AWS wildcards in actions (`s3:Get*`, `s3:*`)
- Resource ARN patterns (`arn:aws:s3:::bucket/*`)
- Policy conditions (IP ranges, time windows, tags, etc.)

#### 4. Query Engine (`internal/query/`)
Traverses the graph to answer access questions:
- **who-can**: Find all principals with a path to a resource+action
- **path**: Find specific paths from principal A to resource B
- **report**: Identify high-risk patterns (public access, overly permissive roles)

**Algorithms:**
- BFS/DFS for path finding
- Consider Deny rules (explicit denies override allows)
- Handle role assumption chains
- Track conditions that must be met

#### 5. CLI (`cmd/aws-access-map/`)
Command-line interface using cobra:
- `collect`: Fetch data from AWS
- `who-can <resource> --action <action>`: Query access
- `path --from <principal> --to <resource> --action <action>`: Find paths
- `report --account <id> --high-risk`: Generate reports

## Development Patterns

### Error Handling
- Use explicit error returns (Go idiom)
- Wrap errors with context: `fmt.Errorf("failed to fetch policies: %w", err)`
- Log errors but continue where possible (one failed API call shouldn't break everything)

### Testing Strategy
- Unit tests for policy parsing (complex logic)
- Integration tests with mock AWS responses
- Example policy files in `testdata/`
- Avoid live AWS API calls in tests

### Performance Considerations
- Cache AWS API responses locally (policies don't change frequently)
- Use goroutines for concurrent AWS API calls
- Keep graph in memory for fast queries
- Consider bloom filters for quick "definitely no access" checks

### Configuration
- Use AWS SDK credential chain (env vars, ~/.aws/credentials, IAM roles)
- Support profile selection: `--profile <name>`
- Cache location: `~/.aws-access-map/cache/`

## Code Style

- Follow standard Go conventions (gofmt, golint)
- Keep functions small and focused
- Prefer explicit over clever
- Document complex policy evaluation logic

## Key Challenges

### 1. Policy Evaluation Complexity
AWS policy evaluation is complex:
- Multiple policy types (identity, resource, SCP, boundaries)
- Deny always wins
- Conditions can be very specific

**MVP approach:**
- Simplified condition evaluation (warn when conditions exist)
- Focus on structural access (ignore most conditions for MVP)
- Add full condition evaluation in v2

### 2. Wildcard Matching
Actions and resources use wildcards:
- `s3:*` matches all S3 actions
- `arn:aws:s3:::bucket/*` matches all objects in bucket

**Solution:**
- Use glob/pattern matching libraries
- Precompute common patterns
- Cache matching results

### 3. Scale
Large AWS accounts have:
- Thousands of IAM policies
- Millions of resources

**Approach:**
- Start with single account, single region
- Add pagination and streaming for large datasets
- Consider external graph DB for very large accounts

## Real-World Testing Insights

**Tested on production AWS account (January 2026):**
- ✅ Successfully collected 3 principals (1 user, 2 service roles)
- ✅ Parsed policies with 1-5 statements each
- ✅ Query time: <100ms for in-memory graph
- ✅ Collection time: ~2-3 seconds for small account

**Key findings:**
1. AWS returns URL-encoded policy documents (need `url.QueryUnescape`)
2. JSON field names: AWS uses `"Statement"` (singular), not `"Statements"`
3. Managed policies require two API calls: `GetPolicy` + `GetPolicyVersion`
4. IAM is global but SDK requires region (default to `us-east-1`)

## Testing Scenarios

### Unit Tests (Priority)
1. **Policy parsing**:
   - URL-encoded documents
   - Wildcard actions (`s3:Get*`, `*`)
   - Multiple statement types (Allow/Deny)
   - Complex principals (maps, arrays, wildcards)

2. **Wildcard matching**:
   - Exact match: `s3:GetObject` matches `s3:GetObject`
   - Prefix match: `s3:Get*` matches `s3:GetObject`
   - Full wildcard: `*` matches everything
   - ARN patterns: `arn:aws:s3:::bucket/*` matches objects

3. **Graph building**:
   - Add principals with multiple policies
   - Handle duplicate entries
   - Process trust policies correctly
   - Edge cases: empty policies, null fields

### Integration Tests
1. **Direct access**: User has policy granting S3 read → `who-can` finds user
2. **Deny rules**: Explicit deny overrides allow → `who-can` doesn't find user
3. **Managed policies**: User with AdministratorAccess → found for `* on *`
4. **Role assumption**: Trust policy allows principal → `path` finds chain (TODO)
5. **Resource policies**: S3 bucket allows public read → `who-can` finds `*` (TODO)

### Real Data Tests
Use `testdata/collected-data.json` from actual AWS account:
```bash
# Verify admin user is found
./build/aws-access-map who-can "*" --action "*"
# Should return: pfrederiksen (user)

# Verify role trust relationships work
jq '.Principals[] | select(.Type == "role") | .TrustPolicy' testdata/collected-data.json
# Should show AWS service principals
```

## Future Enhancements

1. **Condition evaluation**: Full support for policy conditions
2. **Multi-account**: Query across AWS Organizations
3. **Real-time updates**: Watch for policy changes
4. **Visualization**: Export to graph visualization tools
5. **Risk scoring**: Calculate risk scores for access paths
6. **Remediation**: Suggest policy changes to reduce risk

## Debugging Tips

- Use `--debug` flag for verbose output
- Cache AWS responses locally for faster iteration
- Pretty-print graph structure for inspection
- Log policy parsing failures with full policy document

## Resources

- [AWS Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [IAM Policy Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html)
- [AWS SDK Go v2](https://aws.github.io/aws-sdk-go-v2/)
- [Cobra CLI](https://github.com/spf13/cobra)

## Development Workflow

1. Start with small, testable units (policy parser)
2. Build up to integration (collector + graph builder)
3. Add CLI commands incrementally
4. Test with real AWS data early (use personal/test account)
5. Iterate on query engine based on real-world use cases

## Common Implementation Questions

### How do we handle temporary credentials (STS)?
Treat them like regular principals. STS tokens are associated with a role, so query the role's permissions.

### Should we evaluate NotAction and NotResource?
Yes, eventually. For MVP, focus on Action and Resource. NotAction/NotResource are less common but important for completeness.

### How do we represent "public" access in the graph?
Create a synthetic principal with ARN `arn:aws:iam::*:root` or `*`. Treat it as a special node in the graph.

### Do we need to handle cross-account access?
Yes! Trust policies can allow principals from other accounts. Track these as edges in the graph. Multi-account support is phase 2.

### How do we deal with service-specific permission models?
- **S3 ACLs**: Separate from bucket policies, need special handling
- **RDS IAM auth**: Uses IAM but grants DB-level permissions
- **Lambda resource policies**: Control who can invoke
- **Approach**: Start with IAM policies, add resource-specific collectors incrementally

## Implementation Priorities

Based on real-world testing and user needs:

**Phase 1 (MVP - Current)**
1. ✅ IAM policy collection (users, roles, managed policies)
2. ✅ Basic wildcard matching
3. ✅ who-can command
4. ⏳ Enhanced wildcard matching (glob patterns)

**Phase 2 (Next)**
1. Resource policy collection (S3, KMS, SQS, SNS)
2. Role assumption path traversal
3. Deny rule evaluation
4. JSON output mode for scripting

**Phase 3 (Future)**
1. Policy condition evaluation
2. Service Control Policies (SCPs)
3. Multi-account via AWS Organizations
4. Performance optimizations (caching, concurrent collection)

**Phase 4 (Nice-to-have)**
1. Web UI for visualization
2. Export to graph databases (Neo4j)
3. Real-time change detection
4. Policy remediation suggestions

## Example Development Session

**Goal**: Add support for S3 bucket policies

```go
// 1. Add S3 client to collector
type Collector struct {
    iamClient *iam.Client
    s3Client  *s3.Client  // Add this
    ...
}

// 2. Create S3 bucket collector
func (c *Collector) collectS3Buckets(ctx context.Context) ([]*types.Resource, error) {
    // List all buckets
    // For each bucket, get bucket policy
    // Parse policy into Resource struct
}

// 3. Update Collect() to call collectS3Buckets
result.Resources = append(result.Resources, s3Resources...)

// 4. Update graph builder to handle resource policies
// Process resource policies as edges: Resource -> Principal

// 5. Add test
func TestS3BucketPolicyParsing(t *testing.T) {
    // Use testdata/s3-bucket-policy.json
}

// 6. Update docs
// Add to README.md "What it collects" section
```

## Contact

For questions about architecture or implementation decisions:
1. Read this document and README.md
2. Check [TESTING.md](TESTING.md) for known issues
3. Create an issue with your question and use case
4. Tag PRs with relevant context from this doc
