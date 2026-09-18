import json
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3

from .models import Finding


def scan_s3(s3=None) -> list[Finding]:
    s3 = s3 or boto3.client("s3")
    findings = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                pab = {}
            else:
                raise

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public_acl = any(
                grant.get("Grantee", {}).get("URI") ==
                "http://acs.amazonaws.com/groups/global/AllUsers"
                for grant in acl.get("Grants", [])
            )
        except Exception:
            public_acl = False

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            public_policy = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
        except Exception:
            public_policy = False

        block_disabled = (
            pab.get("BlockPublicAcls") is False
            or pab.get("IgnorePublicAcls") is False
            or pab.get("BlockPublicPolicy") is False
            or pab.get("RestrictPublicBuckets") is False
        )

        if public_acl or public_policy or block_disabled:
            findings.append(Finding(
                finding_id=f"S3-PUBLIC-{name}",
                service="S3",
                resource=name,
                severity="HIGH",
                title="S3 bucket may allow public access",
                description="Public ACL/policy exposure or disabled S3 Block Public Access controls were detected.",
                remediation="Enable S3 Block Public Access and review the bucket policy/ACL.",
                metadata={
                    "public_acl": public_acl,
                    "public_policy": public_policy,
                    "block_public_access": pab,
                },
            ))

    return findings


def scan_security_groups(ec2=None) -> list[Finding]:
    ec2 = ec2 or boto3.client("ec2")
    findings = []

    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if from_port is None or to_port is None:
                continue

            exposed_port = None
            if from_port <= 22 <= to_port:
                exposed_port = 22
            elif from_port <= 3389 <= to_port:
                exposed_port = 3389

            if exposed_port is None:
                continue

            unrestricted = any(
                r.get("CidrIp") == "0.0.0.0/0"
                for r in permission.get("IpRanges", [])
            )

            if unrestricted:
                protocol = permission.get("IpProtocol", "-1")
                findings.append(Finding(
                    finding_id=f"SG-OPEN-{sg['GroupId']}-{exposed_port}",
                    service="EC2",
                    resource=sg["GroupId"],
                    severity="CRITICAL" if exposed_port == 22 else "HIGH",
                    title=f"Security group exposes port {exposed_port}",
                    description=f"{sg.get('GroupName', '')} allows {protocol} traffic from 0.0.0.0/0.",
                    remediation=f"Restrict port {exposed_port} to approved source CIDRs or remove the rule.",
                    metadata={"port": exposed_port, "protocol": protocol},
                ))
    return findings


def scan_iam(iam=None, max_age_days: int = 90) -> list[Finding]:
    iam = iam or boto3.client("iam")
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    for user in iam.list_users().get("Users", []):
        username = user["UserName"]

        for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
            create_date = key["CreateDate"]
            if create_date < cutoff and key["Status"] == "Active":
                findings.append(Finding(
                    finding_id=f"IAM-OLD-KEY-{username}-{key['AccessKeyId']}",
                    service="IAM",
                    resource=username,
                    severity="HIGH",
                    title="Active IAM access key exceeds maximum age",
                    description=f"Access key is older than {max_age_days} days.",
                    remediation="Rotate the credential and disable the old access key.",
                    metadata={"access_key_id": key["AccessKeyId"], "created": str(create_date)},
                ))

        for policy in iam.list_user_policies(UserName=username).get("PolicyNames", []):
            document = iam.get_user_policy(UserName=username, PolicyName=policy)["PolicyDocument"]
            if _contains_wildcard_action(document):
                findings.append(Finding(
                    finding_id=f"IAM-WILDCARD-{username}-{policy}",
                    service="IAM",
                    resource=username,
                    severity="HIGH",
                    title="IAM inline policy contains wildcard action",
                    description=f"Inline policy '{policy}' contains Action '*'.",
                    remediation="Replace wildcard permissions with the minimum required actions and resources.",
                    metadata={"policy": policy},
                ))
    return findings


def _contains_wildcard_action(document: dict[str, Any]) -> bool:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        action = statement.get("Action", [])
        if action == "*" or (isinstance(action, list) and "*" in action):
            return True
    return False


def scan_guardduty(guardduty=None) -> list[Finding]:
    guardduty = guardduty or boto3.client("guardduty")
    findings = []

    for detector_id in guardduty.list_detectors().get("DetectorIds", []):
        ids = guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "severity": {"Gte": 7}
                }
            }
        ).get("FindingIds", [])

        if not ids:
            continue

        result = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=ids[:50]
        )

        for item in result.get("Findings", []):
            findings.append(Finding(
                finding_id=f"GD-{item['Id']}",
                service="GuardDuty",
                resource=item.get("Resource", {}).get("ResourceType", "Unknown"),
                severity="CRITICAL" if float(item.get("Severity", 0)) >= 9 else "HIGH",
                title=item.get("Title", "GuardDuty finding"),
                description=item.get("Description", ""),
                remediation="Investigate the finding and follow the organization's incident-response playbook.",
                metadata={"guardduty_severity": item.get("Severity"), "type": item.get("Type")},
            ))
    return findings


def scan_unencrypted_resources(ec2=None, rds=None) -> list[Finding]:
    ec2 = ec2 or boto3.client("ec2")
    rds = rds or boto3.client("rds")
    findings = []

    for volume in ec2.describe_volumes()["Volumes"]:
        if not volume.get("Encrypted", False):
            findings.append(Finding(
                finding_id=f"EBS-UNENCRYPTED-{volume['VolumeId']}",
                service="EBS",
                resource=volume["VolumeId"],
                severity="HIGH",
                title="EBS volume is not encrypted",
                description="The EBS volume is not encrypted at rest.",
                remediation="Migrate data to an encrypted EBS volume according to the approved change procedure.",
                metadata={"size_gib": volume.get("Size")},
            ))

    for db in rds.describe_db_instances()["DBInstances"]:
        if not db.get("StorageEncrypted", False):
            findings.append(Finding(
                finding_id=f"RDS-UNENCRYPTED-{db['DBInstanceIdentifier']}",
                service="RDS",
                resource=db["DBInstanceIdentifier"],
                severity="HIGH",
                title="RDS instance storage is not encrypted",
                description="The database storage is not encrypted at rest.",
                remediation="Create an encrypted replacement using an approved migration/change process.",
                metadata={"engine": db.get("Engine")},
            ))

    return findings
