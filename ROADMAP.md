# Roadmap

## Next Features (Prioritized)

### High Priority
- [ ] Resource policy collection (S3, KMS, SQS, SNS, Secrets Manager)
  - Enables finding access grants from the resource side
  - Critical blind spot in current implementation

- [ ] Transitive access via role chains
  - Find multi-hop paths: User → Role A → Role B → Resource
  - Implement BFS/DFS traversal with cycle detection

- [ ] JSON output mode for scripting
  - `--format json` flag for all commands
  - Enable CI/CD integration and automation

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
- [x] Enhanced wildcard matching (full glob patterns) - v0.1.0
- [x] Comprehensive test coverage (90%+) - v0.1.0
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
