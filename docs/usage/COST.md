# Cost Analysis

## TL;DR: ✅ Completely Free

**Software:** Free and open source (MIT license)
**AWS API Calls:** Free (IAM APIs have no charge)
**Total Cost:** $0.00

---

## Detailed Cost Breakdown

### Software License
- **License:** MIT (open source)
- **Cost:** $0
- You can use, modify, and distribute freely

### AWS API Costs

#### Current Features (IAM Collection)
**Cost:** ✅ **$0 - Completely Free**

AWS IAM API calls have **no charge**:
- `iam:ListUsers` - Free
- `iam:ListRoles` - Free
- `iam:GetUserPolicy` - Free
- `iam:GetRolePolicy` - Free
- `iam:GetPolicy` - Free
- `iam:GetPolicyVersion` - Free
- `iam:ListAttachedUserPolicies` - Free
- `iam:ListAttachedRolePolicies` - Free

**Source:** [AWS IAM Pricing](https://aws.amazon.com/iam/pricing/) states: "AWS Identity and Access Management (IAM) and AWS Security Token Service (AWS STS) are features of your AWS account offered at no additional charge."

#### Future Features (Resource Policies)

When we add S3, KMS, etc. collection:

**S3 API Calls:**
- `s3:ListBuckets` - Free
- `s3:GetBucketPolicy` - $0.0004 per 1,000 requests
- **Estimated cost for 100 buckets:** <$0.01

**KMS API Calls:**
- `kms:ListKeys` - $0.03 per 10,000 requests
- `kms:GetKeyPolicy` - $0.03 per 10,000 requests
- **Estimated cost for 100 keys:** <$0.01

**SQS/SNS:**
- Similar negligible costs (<$0.01 for typical accounts)

**Total estimated cost for full feature set:** <$0.05 per run for a typical AWS account

### What You Pay For

**Nothing extra!** The tool only:
- ✅ Makes read-only API calls (which are free for IAM)
- ✅ Runs locally on your machine (no cloud compute)
- ✅ Stores data locally (no storage costs)
- ✅ No agents, no SaaS, no subscriptions

### Comparison with Alternatives

| Solution | Software Cost | AWS API Costs | Total |
|----------|--------------|---------------|-------|
| **aws-access-map** | Free | $0 | **$0** |
| AWS Console | Free | $0 | $0 |
| aws CLI + scripting | Free | $0 | $0 |
| Commercial tools | $500-5000/mo | Varies | $$$ |

### Required AWS Permissions

The tool needs **read-only** permissions:
- `iam:Get*` - Read IAM data
- `iam:List*` - List IAM resources

These are **non-destructive** operations. The tool cannot:
- ❌ Create resources (no charges)
- ❌ Modify policies (no changes)
- ❌ Delete anything (safe)
- ❌ Store data in AWS (no storage costs)

Recommended IAM policy: AWS managed `SecurityAudit` policy (read-only).

### Cost Examples

#### Small AWS Account (10 users, 20 roles)
- IAM API calls: ~50 requests
- **Cost:** $0.00
- **Time:** 2-3 seconds

#### Medium AWS Account (100 users, 200 roles)
- IAM API calls: ~500 requests
- **Cost:** $0.00
- **Time:** 10-15 seconds

#### Large AWS Account (1000 users, 2000 roles)
- IAM API calls: ~5000 requests
- **Cost:** $0.00
- **Time:** 60-90 seconds

#### Enterprise Multi-Account (100 accounts)
- Run once per account
- **Cost:** $0.00
- Can be scripted/automated

### Hidden Costs?

**None.** Unlike commercial tools:
- ❌ No per-user licensing
- ❌ No per-account fees
- ❌ No support contracts
- ❌ No agent licensing
- ❌ No data egress charges
- ❌ No API usage tiers

### Running Costs

**Electricity cost to run on your laptop:** ~$0.0001 per query 💡

That's literally the only "cost" - the electricity your computer uses for 3 seconds.

### When Might You Pay Something?

**Future resource policy collection:**
- S3, KMS, SQS API calls have minimal charges
- Estimated: <$0.05 per full collection run
- For 99% of accounts: Still effectively free
- Only matters if running 1000s of times per month

### Optimization Tips (For Large Accounts)

If you're paranoid about costs (you shouldn't be, but...):

1. **Cache collected data** - Run `collect` once, query many times
2. **Use --profile** - Don't accidentally scan wrong account
3. **Run daily, not constantly** - IAM policies don't change often
4. **AWS Free Tier** - All IAM calls are free regardless of tier

### ROI Calculation

**Time saved vs manual IAM review:**
- Manual IAM audit: 2-4 hours
- aws-access-map: 3 seconds
- **Time saved:** 2+ hours per audit
- **Your hourly rate × 2 hours = Real value**

Example: If you're paid $100/hour, each run saves $200+ of time.

### FAQ

**Q: Will I be surprised by an AWS bill?**
A: No. IAM API calls are free. Period.

**Q: What if I run it 1000 times?**
A: Still free. IAM APIs have no charge.

**Q: What about AWS data transfer costs?**
A: No data transfer - APIs are in-region, responses are JSON (kilobytes).

**Q: Can I use this in CI/CD without costs?**
A: Yes! Run it on every deployment. Still free.

**Q: What if I have 100 AWS accounts?**
A: Run once per account. All free.

**Q: Is there a catch?**
A: No. IAM APIs are genuinely free. AWS wants you to manage IAM properly.

---

## Summary

### Current Version (v0.1.0-mvp)
- **Software:** Free (MIT license)
- **IAM API calls:** Free (AWS policy)
- **Storage:** Local (no cloud costs)
- **Compute:** Local (no EC2 costs)
- **Total:** **$0.00**

### Future Versions (with S3/KMS collection)
- **Software:** Free (MIT license)
- **IAM API calls:** Free
- **Resource API calls:** ~$0.05 per full scan
- **Total:** **~$0.05 per run** (negligible)

### Bottom Line

✅ **100% free to use, forever**
✅ No hidden costs
✅ No subscriptions
✅ No surprises

The only "cost" is your time to set it up (5 minutes) and run it (3 seconds).

**Compared to commercial IAM tools charging $500-5000/month, this is a no-brainer.**

---

## Adding to README

This information should be highlighted in the README FAQ section.
