# Roadmap

## Next Features (Prioritized)

### High Priority
(No high priority items currently)

### Medium Priority
- [ ] Policy condition evaluation
  - Time-based conditions (aws:CurrentTime)
  - IP-based conditions (aws:SourceIp)
  - Tag-based conditions
  - MFA requirements

- [ ] Caching for faster repeat queries
  - Cache collected AWS data locally
  - Incremental updates
  - Cache invalidation strategies

- [ ] Service Control Policies (SCPs)
  - Collect SCPs from AWS Organizations
  - Apply SCP constraints to access queries
  - Show when SCP blocks access

### Lower Priority
- [ ] Multi-account support via AWS Organizations
  - Cross-account role assumption
  - Aggregate view across organization

- [ ] Web UI for visualization
  - Interactive graph visualization
  - Click to explore access paths
  - Filter and search capabilities

## Completed
- [x] **Role assumption chain traversal** - v0.3.0
  - Multi-hop path finding: User → Role A → Role B → Resource
  - BFS algorithm with cycle detection
  - Max depth limiting (default 5 hops)
  - Finds multiple paths when they exist (up to 10)
  - Test coverage: 87%+ with comprehensive edge cases
- [x] **Resource policy collection** (S3, KMS, SQS, SNS, Secrets Manager) - v0.2.0
  - Collects and parses resource-based policies
  - Creates synthetic public principal for `Principal: "*"`
  - Integrates with graph builder for complete access analysis
- [x] **JSON output mode** for CI/CD automation - v0.2.0
  - `--format json` flag on all commands
  - Clean JSON on stdout, progress on stderr
  - Fully parseable by jq and automation tools
- [x] **Report command** with high-risk pattern detection - v0.2.0
  - Admin Access (CRITICAL): Wildcard permissions
  - Public Access (HIGH/CRITICAL): Anonymous resource access
  - Cross-Account Access (MEDIUM): External account principals
  - Overly Permissive S3 (HIGH): s3:* on all buckets
  - Sensitive Actions (HIGH): IAM/KMS/Secrets/STS access
- [x] Enhanced wildcard matching (full glob patterns) - v0.1.0
- [x] Comprehensive test coverage (95%+) - v0.2.0
- [x] IAM user and role collection - v0.1.0
- [x] Identity-based policy parsing - v0.1.0
- [x] Basic who-can queries - v0.1.0

## Ideas / Future Considerations
- [ ] Plugin system for custom collectors
- [ ] Export to various formats (CSV, GraphML, Neo4j)
- [ ] Integration with AWS Security Hub
- [ ] Anomaly detection (unusual access patterns)
- [ ] Time-series analysis (how access changed over time)
- [ ] Compliance reporting templates (SOC2, ISO 27001)
