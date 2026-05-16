"""Markdown reporter for pull request comments and saved reports."""

from __future__ import annotations

import sys
from pathlib import Path

from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)

RISK_ROW_LABELS = {
    RiskLevel.CRITICAL: "🔴 Critical",
    RiskLevel.HIGH: "🟠 High",
    RiskLevel.MEDIUM: "🟡 Medium",
    RiskLevel.LOW: "🟢 Low",
    RiskLevel.INFO: "ℹ️ INFO",
}

RISK_DISPLAY = {
    RiskLevel.CRITICAL: "🔴 CRITICAL",
    RiskLevel.HIGH: "🟠 HIGH",
    RiskLevel.MEDIUM: "🟡 MEDIUM",
    RiskLevel.LOW: "🟢 LOW",
    RiskLevel.INFO: "ℹ️ INFO",
}


def _workflow_basename(path: str) -> str:
    return Path(path).name


def _auth_display(source: AwsCredentialSource) -> str:
    if source.uses_oidc:
        return "OIDC ✓"
    if source.uses_access_keys:
        return "Static Keys ⚠️"
    return "unknown"


def _critical_concern_lines(finding: PolicyFinding) -> list[str]:
    lines: list[str] = []
    for action in finding.actions:
        if action.action == "iam:PassRole":
            res = action.resource or "*"
            lines.append(
                f"- ⚠️ `{action.action}` on `{res}` — privilege escalation path exists"
            )
        elif action.action == "ec2:TerminateInstances":
            lines.append(
                f"- ⚠️ `{action.action}` — can terminate production instances"
            )
    if finding.has_privilege_escalation and not any(
        a.action == "iam:PassRole" for a in finding.actions
    ):
        lines.append(
            "- ⚠️ Policy enables IAM privilege escalation paths"
        )
    return lines


def _iam_action_row(action: IamAction) -> str:
    risk = RISK_DISPLAY.get(action.risk_level, action.risk_level.name)
    al = action.access_level.replace("|", "\\|")
    return (
        f"| `{action.action}` | {al} | {risk} |"
    )


def _token_workflow_cell(permission: GitHubTokenPermission) -> str:
    wf = _workflow_basename(permission.workflow_file)
    if permission.job_name:
        return f"{wf} (job: {permission.job_name})"
    return f"{wf} (workflow level)"


def _token_table_row(permission: GitHubTokenPermission) -> str:
    scope = permission.scope.replace("|", "\\|")
    access = permission.access.replace("|", "\\|")
    risk = RISK_DISPLAY[permission.risk_level]
    wf = _token_workflow_cell(permission)
    return f"| `{scope}` | {access} | {wf} | {risk} |"


def _binding_section(binding: WorkflowCredentialBinding) -> str:
    src = binding.credential_source
    wf_name = _workflow_basename(src.workflow_file)
    job_label = src.job_name or "(default)"

    lines: list[str] = [
        f"#### `{wf_name}` → `{job_label}` job",
        "",
        "| Field | Value |",
        "|-------|-------|",
    ]

    if src.role_arn:
        role_cell = f"`{src.role_arn}`"
    else:
        role_cell = "`(none)`"

    lines.append(f"| AWS Role | {role_cell} |")
    lines.append(f"| Auth Type | {_auth_display(src)} |")
    lines.append(f"| Policy Source | {binding.policy_source} |")

    if binding.policy_source == "not_found":
        lines.append(
            "| Note | Policy not found in repo. Run with `--aws-verify` flag "
            "to fetch live AWS permissions. |"
        )

    if binding.policy_finding is not None:
        pf = binding.policy_finding
        lines.append(
            f"| Risk | {RISK_DISPLAY[pf.overall_risk]} |",
        )
        lines.append("")

        concerns = _critical_concern_lines(pf)
        if concerns:
            lines.append("**Critical Concerns:**")
            lines.extend(concerns)
            lines.append("")

        if pf.privesc_paths:
            lines.append("**Privilege Escalation Paths:**")
            for path in pf.privesc_paths:
                lines.append(
                    f"- 🔴 **{path.path_name}** — {path.description}"
                )
            lines.append("")

        lines.append("<details>")
        lines.append("<summary>All IAM Actions (click to expand)</summary>")
        lines.append("")
        lines.append("| Action | Access Level | Risk |")
        lines.append("|--------|-------------|------|")
        if pf.actions:
            for a in sorted(pf.actions, key=lambda x: (-x.risk_level.value, x.action)):
                lines.append(_iam_action_row(a))
        else:
            lines.append("| _No actions in policy_ | | |")
        lines.append("")
        lines.append("</details>")
    else:
        lines.append(f"| Risk | {RISK_DISPLAY[RiskLevel.INFO]} |")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>All IAM Actions (click to expand)</summary>")
        lines.append("")
        lines.append("| Action | Access Level | Risk |")
        lines.append("|--------|-------------|------|")
        lines.append("| _No policy matched_ | | |")
        lines.append("")
        lines.append("</details>")

    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _github_token_section(result: ScanResult) -> str:
    if not result.github_token_permissions:
        return ""

    lines = [
        "### GITHUB_TOKEN Permissions",
        "",
        "| Scope | Access | Workflow | Risk |",
        "|-------|--------|----------|------|",
    ]
    for p in result.github_token_permissions:
        lines.append(_token_table_row(p))
    lines.extend(["", "---", ""])
    return "\n".join(lines)


def _summary_table(result: ScanResult) -> str:
    # Count IAM actions by risk across all policy findings in the scan
    counts: dict[RiskLevel, int] = {lvl: 0 for lvl in RiskLevel}
    for pf in result.policy_findings:
        for a in pf.actions:
            counts[a.risk_level] += 1

    rows = [
        "| Risk Level | Count |",
        "|-----------|-------|",
        f"| {RISK_ROW_LABELS[RiskLevel.CRITICAL]} | {counts[RiskLevel.CRITICAL]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.HIGH]} | {counts[RiskLevel.HIGH]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.MEDIUM]} | {counts[RiskLevel.MEDIUM]} |",
        f"| {RISK_ROW_LABELS[RiskLevel.LOW]} | {counts[RiskLevel.LOW]} |",
    ]
    return "\n".join(rows)


def to_markdown(result: ScanResult) -> str:
    """
    Generate a Markdown report suitable for GitHub PR comments.
    """
    cred_count = len(result.credential_sources)
    overall = RISK_DISPLAY.get(result.overall_risk, result.overall_risk.name)

    header = (
        "## 🔍 ActionScope — Blast Radius Report\n\n"
        f"**Overall Risk:** {overall} | **Workflows:** {result.workflow_count} "
        f"| **Credential Sources:** {cred_count}\n\n"
        "---\n\n"
    )

    findings_body = "### Workflow Findings\n\n"
    if result.bindings:
        sections = [_binding_section(b) for b in result.bindings]
        findings_body += "".join(sections)
    else:
        findings_body += "_No workflow credential bindings._\n\n---\n\n"

    token_part = _github_token_section(result)

    summary = (
        "### Summary\n\n"
        f"{_summary_table(result)}\n\n"
        "> Generated by [ActionScope](https://github.com/r12habh/ActionScope)\n"
    )

    return header + findings_body + token_part + summary


def write_markdown(result: ScanResult, output_path: str) -> None:
    """Write Markdown to file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(to_markdown(result))
    except (OSError, UnicodeEncodeError) as exc:
        print(
            f"Warning: could not write Markdown output file {output_path}: {exc}",
            file=sys.stderr,
        )
