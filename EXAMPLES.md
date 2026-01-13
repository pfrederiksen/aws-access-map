# Quick Examples

Copy-paste examples for common tasks. All assume you've already built the tool with `make build`.

## First Time Setup

```bash
# Build the tool
make build

# Verify it works
./build/aws-access-map --help

# Collect data from your AWS account
./build/aws-access-map collect

# Check what was collected
jq '.Principals[] | {Name, Type, PolicyCount: (.Policies | length)}' aws-access-data.json
```

## Security Audits

### Find all admin users
```bash
# Who has god-mode access?
./build/aws-access-map who-can "*" --action "*"

# Example output:
# Found 1 principal(s) with access:
#   alice (user)
#     ARN: arn:aws:iam::123456789012:user/alice
```

### Check specific permissions
```bash
# Who can access S3 buckets?
./build/aws-access-map who-can "arn:aws:s3:::*" --action "s3:*"

# Who can read secrets?
./build/aws-access-map who-can "arn:aws:secretsmanager:*:*:secret/*" --action "secretsmanager:GetSecretValue"

# Who can manage IAM?
./build/aws-access-map who-can "arn:aws:iam::*:*" --action "iam:*"
```

## Debugging Permission Issues

### Lambda can't access S3
```bash
# Check if Lambda role can access bucket
./build/aws-access-map path \
  --from arn:aws:iam::123456789012:role/MyLambdaExecutionRole \
  --to "arn:aws:s3:::my-bucket/*" \
  --action s3:GetObject

# If "No access paths found", add the permission
```

### Service can't decrypt KMS key
```bash
# Check who can decrypt a specific key
./build/aws-access-map who-can \
  "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-5678-90ef" \
  --action kms:Decrypt
```

## Compliance & Auditing

### Export collected data for review
```bash
# Collect and format for easy reading
./build/aws-access-map collect --output audit-$(date +%Y%m%d).json

# List all users
jq '.Principals[] | select(.Type == "user") | .Name' audit-*.json

# List all roles
jq '.Principals[] | select(.Type == "role") | .Name' audit-*.json

# Count policies per principal
jq '.Principals[] | {Name, PolicyCount: (.Policies | length)}' audit-*.json
```

### Find users with inline policies
```bash
# Inline policies are often forgotten during reviews
jq '.Principals[] | select(.Policies | length > 0) | {
  Name,
  Type,
  InlinePolicyCount: (.Policies | length)
}' aws-access-data.json
```

## Incident Response

### A key was exposed - what can it access?
```bash
# 1. Find the exposed user/role
./build/aws-access-map collect
grep "exposed-user-name" aws-access-data.json

# 2. Check if they have admin access
./build/aws-access-map who-can "*" --action "*" | grep "exposed-user-name"

# 3. Look at their policies
jq '.Principals[] | select(.Name == "exposed-user-name") | .Policies' aws-access-data.json
```

### Check cross-account access
```bash
# Find roles with trust policies allowing external accounts
jq '.Principals[] | select(.Type == "role" and .TrustPolicy != null) | {
  Name,
  TrustPolicy: .TrustPolicy.Statement
}' aws-access-data.json | grep -B5 "arn:aws:iam::[0-9]"
```

## IAM Groups (v0.7.0)

### Find users with access via groups
```bash
# Users inherit permissions from groups
./build/aws-access-map who-can "arn:aws:s3:::*" --action "s3:GetObject"

# Example output:
#   alice (user) - via group: Developers
#   bob (user) - via group: Developers
#   Developers (group)
```

### Check group membership
```bash
# List all groups
jq '.Principals[] | select(.Type == "group") | .Name' aws-access-data.json

# Find users in specific group
jq '.Principals[] | select(.GroupMemberships[]? | contains("Developers")) | .Name' aws-access-data.json
```

### Verify group deny rules
```bash
# Group denies override user allows
# If group has Deny for s3:DeleteObject, user won't have access even if their policy allows it
./build/aws-access-map who-can "arn:aws:s3:::bucket/*" --action "s3:DeleteObject"
```

## Serverless Access Patterns (v0.7.0)

### Lambda function access
```bash
# Who can invoke this Lambda?
./build/aws-access-map who-can \
  "arn:aws:lambda:us-east-1:123456789012:function:my-function" \
  --action "lambda:InvokeFunction"

# Common use case: Debug "User is not authorized to perform: lambda:InvokeFunction"
```

### API Gateway access
```bash
# Who can call this API?
./build/aws-access-map who-can \
  "arn:aws:execute-api:us-east-1:123456789012:abc123/*/*/*" \
  --action "execute-api:Invoke"
```

### ECR repository access
```bash
# Who can pull container images?
./build/aws-access-map who-can \
  "arn:aws:ecr:us-east-1:123456789012:repository/my-app" \
  --action "ecr:BatchGetImage"

# Common use case: CI/CD pipeline can't pull images
```

### EventBridge event bus access
```bash
# Who can publish events?
./build/aws-access-map who-can \
  "arn:aws:events:us-east-1:123456789012:event-bus/custom-bus" \
  --action "events:PutEvents"
```

## Policy Testing & Simulation (v0.7.0)

### Test policy before deployment
```bash
# 1. Collect current policies
./build/aws-access-map collect -o prod-current.json

# 2. Create test policy
cat > test-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  }]
}
EOF

# 3. Test without deploying to AWS
./build/aws-access-map simulate test \
  --data prod-current.json \
  --add-policy test-policy.json \
  --principal "arn:aws:iam::123456789012:role/MyRole"

# Output shows if policy is overly permissive
```

### Compare policy versions
```bash
# Save before snapshot
./build/aws-access-map collect -o before.json

# Make AWS changes...

# Save after snapshot
./build/aws-access-map collect -o after.json

# Compare
./build/aws-access-map simulate diff \
  --before before.json \
  --after after.json \
  --action "*"

# Output shows who gained/lost access
```

### CI/CD policy validation
```bash
#!/bin/bash
# validate-policies.sh

# Validate no security issues (exits 1 if problems found)
./build/aws-access-map simulate validate --data proposed-policies.json

if [ $? -ne 0 ]; then
  echo "❌ Security issues detected in policies"
  exit 1
fi

echo "✅ Policies validated successfully"
```

### Local development without AWS
```bash
# Test policies on your laptop (no AWS credentials needed)
./build/aws-access-map simulate who-can "*" --action "s3:*" \
  --data test-policies.json
```

## Incremental Collection (v0.7.0)

### Faster collection for large accounts
```bash
# First run: full collection (baseline)
time ./build/aws-access-map collect --no-cache -o data.json
# Time: 30 seconds (1000 resources)

# Subsequent runs: incremental (delta only)
time ./build/aws-access-map collect --incremental -o data.json
# Time: 3 seconds (no changes)

# After AWS change
aws s3api put-bucket-policy --bucket my-bucket --policy file://policy.json

# Incremental detects and fetches only changed resource
time ./build/aws-access-map collect --incremental -o data.json
# Time: 5 seconds (1 changed resource)
```

### View incremental statistics
```bash
# Enable debug to see what changed
./build/aws-access-map collect --incremental --debug

# Example output:
# === Incremental Collection Stats ===
# Mode: incremental
# Duration: 3.45 seconds
# Resources Fetched: 10
# Resources Cached: 990
# Change Percentage: 1.00%
```

### Use in CI/CD for speed
```bash
#!/bin/bash
# fast-ci-check.sh

# First CI run: full collection
./build/aws-access-map collect --no-cache -o baseline.json

# Subsequent CI runs: incremental (10x faster)
./build/aws-access-map collect --incremental -o data.json

# Run security checks
./build/aws-access-map who-can "*" --action "*"
```

## CI/CD Integration

### Validate deployments don't grant excessive permissions
```bash
#!/bin/bash
# In your CI/CD pipeline

# Collect current state
./build/aws-access-map collect --output before.json

# Deploy your changes
terraform apply -auto-approve

# Collect new state
./build/aws-access-map collect --output after.json

# Check for new admins
BEFORE=$(./build/aws-access-map who-can "*" --action "*" | grep -c "ARN:")
AFTER=$(./build/aws-access-map who-can "*" --action "*" | grep -c "ARN:")

if [ $AFTER -gt $BEFORE ]; then
  echo "ERROR: New admin users detected!"
  exit 1
fi
```

## Offboarding

### Verify user was fully removed
```bash
# Check if username appears anywhere
./build/aws-access-map collect
grep -i "contractor-name" aws-access-data.json

# Check for roles they could assume
jq '.Principals[] | select(.TrustPolicy.Statement[]?.Principal | contains("contractor"))' aws-access-data.json
```

## Multi-Profile Support

### Query production account
```bash
./build/aws-access-map collect --profile prod --output prod-account.json
./build/aws-access-map who-can "*" --action "*" --profile prod
```

### Query staging account
```bash
./build/aws-access-map collect --profile staging --output staging-account.json
./build/aws-access-map who-can "*" --action "*" --profile staging
```

### Compare accounts
```bash
# Count admins in each
echo "Prod admins:"
./build/aws-access-map who-can "*" --action "*" --profile prod | grep -c "ARN:"

echo "Staging admins:"
./build/aws-access-map who-can "*" --action "*" --profile staging | grep -c "ARN:"
```

## Advanced jq Queries

### Find users with most policies
```bash
jq -r '.Principals[] | "\(.Policies | length)\t\(.Name)\t\(.Type)"' aws-access-data.json | sort -rn
```

### Extract all policy statements
```bash
jq '.Principals[] | .Policies[] | .Statement[]' aws-access-data.json > all-statements.json
```

### Find policies with wildcards
```bash
jq '.Principals[] | select(.Policies[].Statement[]? | .Action == "*" or .Resource == "*") | {
  Name,
  Type,
  Policies: [.Policies[].Statement[] | select(.Action == "*" or .Resource == "*")]
}' aws-access-data.json
```

### Find all S3 permissions
```bash
jq '.Principals[] | {
  Name,
  S3Actions: [.Policies[].Statement[]? | select(.Action | tostring | startswith("s3:") or . == "*") | .Action]
} | select(.S3Actions | length > 0)' aws-access-data.json
```

## Tips

1. **Cache collected data**: Run `collect` once, query many times
2. **Use profiles**: `--profile` flag for multi-account setups
3. **JSON output**: Collected data is JSON, use `jq` for complex queries
4. **Automation**: Script it! Add to CI/CD, cron jobs, incident runbooks
5. **Diff over time**: Save collections periodically, compare with `diff`

## Troubleshooting

### No results found
```bash
# Make sure you collected data first
./build/aws-access-map collect

# Check collection worked
jq '.Principals | length' aws-access-data.json
# Should show number > 0

# Try broader query
./build/aws-access-map who-can "*" --action "*"
```

### AWS credentials not found
```bash
# Check credentials are configured
aws sts get-caller-identity

# Or specify profile
./build/aws-access-map collect --profile your-profile-name
```

### Permissions denied
```bash
# You need read permissions for IAM
# Attach this AWS managed policy: SecurityAudit (arn:aws:iam::aws:policy/SecurityAudit)
# Or create custom policy with: iam:Get*, iam:List*
```
