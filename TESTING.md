# Testing Results

## Test Run: 2026-01-12

### Real AWS Data Collection ✅

Successfully tested against AWS account 571667117138:

```bash
./build/aws-access-map collect --output testdata/collected-data.json
```

**Results:**
- ✅ Collected 3 principals (1 user, 2 roles)
- ✅ Successfully fetched inline policies
- ✅ Successfully fetched attached managed policies (AdministratorAccess, Billing)
- ✅ Parsed policy documents with URL decoding
- ✅ Extracted 1-5 statements per policy
- ✅ Parsed trust policies for roles

**Data collected:**
- **User**: pfrederiksen
  - Inline policy: CostExplorer (1 statement)
  - Managed policies: AdministratorAccess (1 statement), Billing (multiple statements)
- **Roles**: AWSServiceRoleForSupport, AWSServiceRoleForTrustedAdvisor
  - With trust policies and attached managed policies

### who-can Command ✅

```bash
./build/aws-access-map who-can "*" --action "*"
```

**Results:**
- ✅ Successfully queries the graph
- ✅ Found principal with `*` permissions (AdministratorAccess)
- ⚠️  Wildcard matching is simplified - only exact matches work

### Issues Fixed During Testing

1. **Region Configuration**: IAM is global but SDK required region
   - **Fix**: Default to `us-east-1` if no region specified

2. **URL-Encoded Policies**: AWS returns policies URL-encoded
   - **Fix**: Used `policy.Parse()` function with URL decoding

3. **JSON Field Mismatch**: AWS uses `"Statement"` (singular), struct used `Statements` (plural)
   - **Fix**: Added JSON struct tags with correct field name mapping

4. **Missing Managed Policies**: Only collected inline policies initially
   - **Fix**: Implemented `ListAttachedUserPolicies`, `ListAttachedRolePolicies`, and `GetPolicyVersion`

## Known Limitations (MVP)

### Wildcard Matching
Currently only exact and simple prefix matching (`*` suffix):
- ✅ `*` matches everything
- ✅ `s3:Get*` matches `s3:GetObject`
- ❌ `arn:aws:s3:::bucket/*` doesn't properly match specific objects
- ❌ `s3:*Object` (wildcard in middle) not supported

**Impact**: A principal with `Action: "*"` or `Resource: "*"` won't be found when querying for specific actions/resources.

**TODO**: Implement full AWS wildcard matching using glob patterns.

### Condition Evaluation
Policy conditions are detected but not evaluated:
- Time-based conditions
- IP-based conditions
- Tag-based conditions
- MFA requirements

**Impact**: Tool may report access that's actually blocked by conditions.

**TODO**: Implement condition evaluation engine.

### Resource Collection
Currently only collects IAM principals, not resources:
- No S3 bucket policies
- No KMS key policies
- No SQS/SNS resource policies

**Impact**: Cannot detect resource-based access grants.

**TODO**: Add collectors for resource policies.

### Transitive Access
Path finding doesn't follow role assumption chains yet:
- Can't find multi-hop access (User → Role A → Role B → Resource)

**Impact**: Miss complex access paths through role chaining.

**TODO**: Implement BFS/DFS path traversal with role assumptions.

## Next Steps for Production

1. **Enhanced Wildcard Matching** - Use golang glob library for full AWS pattern support
2. **Resource Policy Collection** - Add S3, KMS, SQS, SNS, Secrets Manager collectors
3. **Transitive Path Finding** - Implement graph traversal for role chains
4. **Caching** - Cache collected data locally to avoid repeated API calls
5. **Condition Evaluation** - Parse and evaluate policy conditions
6. **Service Control Policies** - Collect and evaluate SCPs from AWS Organizations
7. **Performance** - Add concurrency for large accounts
8. **Output Formats** - Add JSON output mode for programmatic use

## Performance

Collection time for small account (3 principals):
- ~2-3 seconds (includes API pagination)

Query time:
- <100ms (in-memory graph traversal)

## Verification

To verify the collected data matches AWS:

```bash
# Check user policies
aws iam list-user-policies --user-name pfrederiksen
aws iam list-attached-user-policies --user-name pfrederiksen

# Compare with collected data
jq '.Principals[] | select(.Type == "user") | {Name, PolicyCount: (.Policies | length)}' testdata/collected-data.json
```

All data matches! ✅
