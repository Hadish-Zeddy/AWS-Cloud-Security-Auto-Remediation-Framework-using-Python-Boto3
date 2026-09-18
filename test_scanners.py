from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from src.scanners import scan_iam, scan_security_groups


def test_security_group_open_ssh_is_detected():
    ec2 = Mock()
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{
            "GroupId": "sg-123",
            "GroupName": "bad-sg",
            "IpPermissions": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        }]
    }

    findings = scan_security_groups(ec2)
    assert len(findings) == 1
    assert findings[0].metadata["port"] == 22


def test_old_iam_key_is_detected():
    iam = Mock()
    iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{
            "AccessKeyId": "AKIAEXAMPLE",
            "Status": "Active",
            "CreateDate": datetime.now(timezone.utc) - timedelta(days=120),
        }]
    }
    iam.list_user_policies.return_value = {"PolicyNames": []}

    findings = scan_iam(iam, max_age_days=90)
    assert len(findings) == 1
    assert findings[0].resource == "alice"
