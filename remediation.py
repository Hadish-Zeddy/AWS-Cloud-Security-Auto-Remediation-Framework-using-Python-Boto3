import boto3

from .models import Finding


def remediate_s3(finding: Finding, s3=None) -> bool:
    s3 = s3 or boto3.client("s3")
    bucket = finding.resource

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    return True


def remediate_security_group(finding: Finding, ec2=None) -> bool:
    ec2 = ec2 or boto3.client("ec2")
    sg_id = finding.resource
    port = int(finding.metadata["port"])
    protocol = finding.metadata["protocol"]

    # Revoke only the unrestricted IPv4 rule for the affected port.
    ec2.revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": protocol,
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    return True


def remediate_old_iam_key(finding: Finding, iam=None) -> bool:
    iam = iam or boto3.client("iam")
    username = finding.resource
    access_key_id = finding.metadata["access_key_id"]

    # Disabling is reversible and safer than immediate deletion.
    iam.update_access_key(
        UserName=username,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
    return True


def remediate(finding: Finding) -> bool:
    if finding.service == "S3":
        return remediate_s3(finding)

    if finding.service == "EC2":
        return remediate_security_group(finding)

    if finding.service == "IAM" and finding.title.startswith("Active IAM"):
        return remediate_old_iam_key(finding)

    # GuardDuty, EBS and RDS remediation requires investigation/change control.
    return False
