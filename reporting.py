import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding


def write_report(findings: list[Finding], report_dir: str) -> tuple[Path, Path]:
    Path(report_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.as_dict() for f in findings],
    }

    json_path = Path(report_dir) / f"security-report-{stamp}.json"
    md_path = Path(report_dir) / f"security-report-{stamp}.md"

    json_path.write_text(json.dumps(payload, indent=2, default=str))

    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        "# AWS Cloud Security Report",
        "",
        f"Generated: {payload['generated_at']}",
        f"Total findings: {len(findings)}",
        "",
        "## Severity Summary",
        "",
    ]

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {severity}: {counts.get(severity, 0)}")

    lines += ["", "## Findings", ""]
    for f in findings:
        lines += [
            f"### [{f.severity}] {f.title}",
            f"- Service: `{f.service}`",
            f"- Resource: `{f.resource}`",
            f"- Description: {f.description}",
            f"- Recommended remediation: {f.remediation}",
            f"- Remediated: `{f.remediated}`",
            "",
        ]

    md_path.write_text("\n".join(lines))
    return json_path, md_path
