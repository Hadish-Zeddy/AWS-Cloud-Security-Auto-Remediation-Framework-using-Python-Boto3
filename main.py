from .config import (
    AWS_REGION,
    IAM_KEY_MAX_AGE_DAYS,
    REMEDIATION_ENABLED,
    REPORT_DIR,
)
from .models import Finding
from .remediation import remediate
from .reporting import write_report
from .scanners import (
    scan_guardduty,
    scan_iam,
    scan_s3,
    scan_security_groups,
    scan_unencrypted_resources,
)


def run() -> list[Finding]:
    import boto3

    session = boto3.Session(region_name=AWS_REGION)

    findings: list[Finding] = []

    findings.extend(scan_s3(session.client("s3")))
    findings.extend(scan_security_groups(session.client("ec2")))
    findings.extend(scan_iam(session.client("iam"), IAM_KEY_MAX_AGE_DAYS))
    findings.extend(scan_guardduty(session.client("guardduty")))
    findings.extend(
        scan_unencrypted_resources(
            session.client("ec2"),
            session.client("rds"),
        )
    )

    if REMEDIATION_ENABLED:
        for finding in findings:
            try:
                finding.remediated = remediate(finding)
            except Exception as exc:
                # Keep scanning/reporting even if one remediation fails.
                finding.metadata["remediation_error"] = str(exc)

    json_path, md_path = write_report(findings, REPORT_DIR)

    print(f"Findings: {len(findings)}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")

    return findings


if __name__ == "__main__":
    run()
