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
