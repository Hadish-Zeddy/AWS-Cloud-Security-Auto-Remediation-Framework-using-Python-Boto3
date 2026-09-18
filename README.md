# Terraform deployment extension

A production deployment can package `src/main.py` as a Lambda function and trigger it with EventBridge.

Recommended resources:

- Lambda execution role with least-privilege read permissions
- Optional remediation permissions separated into a second role
- EventBridge scheduled rule
- CloudWatch log group
- SNS topic for findings
- S3 bucket for reports with encryption enabled

Keep `REMEDIATION_ENABLED=false` for the first deployment and promote remediation only after testing.
