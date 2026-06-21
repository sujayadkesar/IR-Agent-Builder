# AWS Production Setup

Step-by-step setup for the AWS infrastructure that backs the DFIR Agent Builder. Do this **once per organization**, then every collector build references the same bucket / KMS key / IAM policy template.

This guide assumes you have AWS Organizations and root access (or an AdministratorAccess role) in the target account.

## 1. Forensics AWS account

Create a new AWS account dedicated to forensic evidence. Why a separate account?

- **Blast radius isolation** — production breach can't read evidence.
- **Easier audit** — every API call in this account is forensic activity.
- **Distinct billing** — IR storage costs don't pollute prod ledgers.

```
AWS Organizations → Add an AWS account → Create AWS account
  Name: forensics-prod
  Email: forensics-aws+root@yourorg.com
```

Enable account-level **Block Public Access** for S3 immediately. CloudTrail multi-region trail. AWS Config compliance pack. GuardDuty. (These are checkbox items in the consoles.)

## 2. KMS Customer Managed Key

Region: pick the closest to where most endpoints are. For India IR teams, `ap-south-1` (Mumbai). For multi-region collection, use a Multi-Region Key.

```
KMS → Customer-managed keys → Create key
  Key type: Symmetric
  Key usage: Encrypt and decrypt
  Multi-region: Yes (if collecting in multiple regions)
  Alias: alias/dfir-evidence-cmk
  Key administrators: ir-engineering-admins (IAM group / SSO group)
  Key users: (leave empty — we attach via policy below)
  Automatic rotation: Enabled
```

Attach this key policy (replacing account ID and ARNs):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRoot",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowCollectorEncrypt",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["kms:GenerateDataKey", "kms:Encrypt"],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:user/dfir-collector-*"
        }
      }
    },
    {
      "Sid": "AllowAnalystDecrypt",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:role/ir-analyst-evidence-reader"
        }
      }
    }
  ]
}
```

Copy the resulting ARN — you'll paste it into the wizard's **SSE-KMS Key ARN** field on Step 3.

## 3. S3 evidence bucket

```
S3 → Create bucket
  Name: ir-evidence-<orgname>-<year>     (e.g. ir-evidence-acmecorp-2026)
  Region: same as KMS key
  Block all public access: ON (default)
  Bucket Versioning: Enable
  Object Lock: Enable
    → After creation, set default retention: COMPLIANCE mode, 365 days
  Default encryption:
    Server-side encryption: SSE-KMS
    KMS key: alias/dfir-evidence-cmk (the one from step 2)
```

**Important** — Object Lock can only be enabled at bucket creation. If you forget, you must recreate the bucket.

After creation, attach this bucket policy (deny non-HTTPS, deny non-encrypted, deny delete from everyone including root):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonHTTPS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::ir-evidence-acmecorp-2026",
        "arn:aws:s3:::ir-evidence-acmecorp-2026/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyUnencryptedPut",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::ir-evidence-acmecorp-2026/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "DenyDeleteEveryone",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:DeleteBucket"
      ],
      "Resource": [
        "arn:aws:s3:::ir-evidence-acmecorp-2026",
        "arn:aws:s3:::ir-evidence-acmecorp-2026/*"
      ]
    }
  ]
}
```

Add lifecycle rules (cost optimization):
- Day 90: transition to S3 Glacier Instant Retrieval.
- Day 180: transition to S3 Glacier Deep Archive.
- **Abort incomplete multipart uploads after 7 days** (recommended). The collector
  uploads large containers via S3 multipart and retries/resumes across network
  outages and interruptions; if a run can never finish (endpoint decommissioned,
  upload abandoned), the partial multipart would otherwise linger and accrue storage
  cost. This rule reaps them. Note the per-build IAM policy is write-only and does
  **not** grant `s3:AbortMultipartUpload`, so the collector's own best-effort abort
  on a permanent error may be denied — this lifecycle rule is the reliable cleanup.

Add an SNS notification on `s3:ObjectCreated:Put` to your IR oncall email — you'll get a real-time alert when any endpoint uploads new evidence.

## 4. Per-build IAM user

For **every build** you create from the wizard, create a fresh IAM user. The wizard's "Generate IAM Policy" button gives you the exact JSON to attach.

```
IAM → Users → Create user
  Username: dfir-collector-<build-id>     (e.g. dfir-collector-a3f9b221)
  Console access: NO (programmatic only)

  Permissions: Attach inline policy → paste JSON from wizard
  Tags:
    build-id:    <build-id>
    build-date:  2026-05-06
    artifact-set: SANSTriage
    created-by:  <ir-engineer-email>

  Create access key:
    Use case: Other (third-party service)
    Description: dfir-collector-<build-id>

  → Download CSV (this is the only chance — paste into the wizard's Step 3 form)
```

Set a calendar reminder: rotate this access key after **90 days**, which means rebuild the collector and redeploy via GPO. The wizard's audit ledger tracks build dates.

## 5. IR analyst read-only role

Used by the team to download and decrypt evidence. **Never embedded** in any binary.

```
IAM → Roles → Create role
  Trusted entity: SAML 2.0 federation (AWS SSO) or trusted account
  Permissions:
    s3:GetObject, s3:ListBucket, s3:GetObjectVersion → on the evidence bucket
    kms:Decrypt, kms:DescribeKey → on the CMK
  Trust policy condition:
    aws:MultiFactorAuthPresent = true
    aws:SourceIp = corporate VPN CIDRs
  Session duration: 4 hours
```

## 6. Verify

Use the wizard's **Validate connection** button on Step 3. It performs a tiny PutObject (16 bytes) to a sentinel key. A successful 200 means the collector will be able to upload. Check the resulting object in the S3 console — it should show `aws:kms` SSE.

## 7. AWS Transfer Family SFTP (optional, max-security)

For the highest-security posture (no AWS keys ever embedded in any binary), use AWS Transfer Family SFTP backed by S3. The collector embeds only an SSH private key.

```
Transfer Family → Create server
  Identity provider: Service-managed
  Endpoint type: VPC / Public
  Domain: S3
  Add user:
    Username: dfir-collector-sftp
    SSH public key: <generate ed25519 keypair, paste public>
    Home directory: /<bucket>/<build-id>
    Restricted: YES
    Policy: scope-down to s3:PutObject only
```

The SFTP option is on the roadmap for the wizard (Step 3 already shows it, but it's not yet wired through the collector binary).

## Cost estimate (ap-south-1)

For a 1000-endpoint deployment running QuickTriage weekly:

| Item | Volume | Monthly cost (USD) |
|------|--------|--------------------|
| S3 Standard storage | 1000 × 200MB × 4 weeks ÷ Glacier transition = ~200 GB | ~$5 |
| S3 Standard requests (PUT) | ~20K | ~$0.10 |
| KMS CMK | 1 key + 20K GenerateDataKey | ~$1 + $0.06 |
| CloudTrail | included | $0 |
| GuardDuty | sub-$1 for this volume | ~$1 |
| **Total** | | **~$10/month** |

For Deep Dive / RAM dumps the storage line dominates — add ~$0.023/GB.
