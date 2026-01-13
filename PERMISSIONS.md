# IAM Permissions Required

This document details the AWS IAM permissions required to run `aws-access-map` successfully.

## Overview

`aws-access-map` collects IAM policies, resource policies, and optionally Service Control Policies (SCPs) from your AWS account. The permissions required depend on which features you use and what resources you want to analyze.

## Minimum Required Permissions

These permissions are required for basic functionality (collecting IAM principals and policies):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

## Resource Policy Permissions

To collect resource-based policies (S3, KMS, SQS, SNS, Secrets Manager), add these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KMSResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:GetKeyPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SQSResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "sqs:ListQueues",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SNSResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "sns:ListTopics",
        "sns:GetTopicAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:GetResourcePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

## Service Control Policy (SCP) Permissions

To collect SCPs from AWS Organizations (using `--include-scps` flag), add these permissions:

**Important**: These permissions are only needed if you run `aws-access-map collect --include-scps`. Regular queries don't require Organizations access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrganizationsSCPAccess",
      "Effect": "Allow",
      "Action": [
        "organizations:ListPolicies",
        "organizations:DescribePolicy",
        "organizations:ListTargetsForPolicy",
        "organizations:ListParents"
      ],
      "Resource": "*"
    }
  ]
}
```

### SCP Permission Details

- **`organizations:ListPolicies`**: Lists all Service Control Policies in the organization
- **`organizations:DescribePolicy`**: Retrieves the policy document for each SCP
- **`organizations:ListTargetsForPolicy`**: Determines which accounts/OUs each SCP is attached to
- **`organizations:ListParents`**: Traverses OU hierarchy to determine which OUs the account belongs to (for accurate SCP filtering)

### Organizations Access Considerations

1. **Management Account vs. Member Account**:
   - SCPs are typically managed in the **management account** (formerly master account)
   - Member accounts may not have permission to read organization-wide SCPs
   - Run `aws-access-map collect --include-scps` from the management account for best results

2. **Delegated Administrator**:
   - If you've delegated Organizations administration, that account can also collect SCPs
   - Ensure the delegated admin account has the Organizations SCP permissions above

3. **Graceful Degradation**:
   - If Organizations permissions are denied, `aws-access-map` will continue without SCPs
   - You'll see a debug message: `"No Organizations access, skipping SCPs"`
   - Regular IAM and resource policy analysis will still work

## Complete IAM Policy Example

Here's a complete IAM policy with all permissions for full `aws-access-map` functionality:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadAccess",
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListRoles",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ResourcePolicyAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "kms:ListKeys",
        "kms:GetKeyPolicy",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetResourcePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "OrganizationsSCPAccess",
      "Effect": "Allow",
      "Action": [
        "organizations:ListPolicies",
        "organizations:DescribePolicy",
        "organizations:ListTargetsForPolicy",
        "organizations:ListParents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Applying the Policy

### Option 1: Attach to IAM User

```bash
# Create the policy
aws iam create-policy \
  --policy-name AWSAccessMapReadOnly \
  --policy-document file://aws-access-map-policy.json

# Attach to user
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::123456789012:policy/AWSAccessMapReadOnly
```

### Option 2: Attach to IAM Role (for EC2/Lambda/etc.)

```bash
# Attach to role
aws iam attach-role-policy \
  --role-name your-role-name \
  --policy-arn arn:aws:iam::123456789012:policy/AWSAccessMapReadOnly
```

### Option 3: Use AWS Managed Policies (Less Privileged Alternative)

For basic IAM analysis only, you can use existing AWS managed policies:

- **`SecurityAudit`** - Provides read-only access to security configuration (includes IAM, S3 policies, etc.)
- **`ViewOnlyAccess`** - Broader read-only access to AWS resources

```bash
# Attach SecurityAudit managed policy
aws iam attach-user-policy \
  --user-name your-username \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

**Note**: `SecurityAudit` does NOT include Organizations permissions. You'll need to add the Organizations SCP permissions separately if using `--include-scps`.

## Testing Your Permissions

To verify you have the required permissions:

```bash
# Test basic IAM collection
./aws-access-map collect -o test-data.json

# Test with SCPs (requires Organizations permissions)
./aws-access-map collect --include-scps -o test-data.json

# Test with specific profile
./aws-access-map collect --profile myprofile --include-scps -o test-data.json
```

If you see errors like:

- `AccessDenied` or `UnauthorizedOperation` - You're missing required permissions
- `No Organizations access, skipping SCPs` - Normal if not using management account or lacking Organizations permissions
- `failed to list users` - Missing IAM read permissions

## Least Privilege Recommendations

1. **Start Minimal**: Begin with just IAM read permissions, add resource policies as needed
2. **Separate SCP Collection**: Only grant Organizations permissions to management account users who need it
3. **Read-Only**: All permissions are read-only (`Get`, `List`, `Describe`) - no write operations needed
4. **Audit Trail**: Enable CloudTrail to monitor usage of these permissions
5. **Time-Bound**: Consider using temporary credentials (STS AssumeRole) for security audits

## Troubleshooting

### "AccessDenied" for Organizations APIs

**Symptom**: `failed to collect SCPs: AccessDeniedException`

**Cause**: Not running from management account, or missing Organizations permissions

**Solutions**:
1. Run from the AWS Organizations management account
2. Verify Organizations permissions are attached to your user/role
3. If not needed, run without `--include-scps` flag

### "User: ... is not authorized to perform: iam:GetUser"

**Symptom**: `failed to get account ID: AccessDenied`

**Cause**: Missing IAM GetUser permission

**Solution**: Add `iam:GetUser` action to your policy

### "Resource policies not collected"

**Symptom**: S3/KMS/SQS/SNS resources missing or no policies shown

**Cause**: Missing resource-specific permissions

**Solution**: Add the resource policy permissions for the specific services you need (S3, KMS, etc.)

## Security Considerations

1. **Credential Storage**: `aws-access-map` uses the AWS SDK credential chain (environment variables, ~/.aws/credentials, IAM roles)
2. **No Write Operations**: All operations are read-only - tool cannot modify policies or resources
3. **Data Handling**: Collected data is stored locally in JSON format - protect this file as it contains sensitive policy information
4. **SCP Visibility**: SCPs reveal organization-level controls - limit access to management account
5. **Audit Usage**: Monitor CloudTrail logs for unusual patterns of IAM/Organizations API calls

## Additional Resources

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Organizations SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AWS Policy Evaluation Logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
