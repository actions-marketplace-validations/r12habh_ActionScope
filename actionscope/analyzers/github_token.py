"""GITHUB_TOKEN permission analyzer for workflow-level and job-level scopes."""

from __future__ import annotations

from typing import Any

from actionscope.models import GitHubTokenPermission, RiskLevel

KNOWN_PERMISSION_SCOPES = (
    "actions",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
)

HIGH_WRITE_SCOPES = {"pull-requests", "packages", "id-token"}
MEDIUM_WRITE_SCOPES = {"contents", "actions", "deployments"}


def analyze_workflow_permissions(
    workflow_data: dict,
    workflow_file: str,
) -> list[GitHubTokenPermission]:
    """Return GITHUB_TOKEN permission findings from parsed workflow YAML."""
    if not isinstance(workflow_data, dict):
        return []

    findings: list[GitHubTokenPermission] = []

    if "permissions" in workflow_data and workflow_data["permissions"] is not None:
        findings.extend(
            _permissions_to_findings(
                permissions=workflow_data["permissions"],
                workflow_file=workflow_file,
                job_name="",
                oidc_expected=_workflow_uses_role_to_assume(workflow_data),
            )
        )

    jobs = workflow_data.get("jobs")
    if jobs is None:
        jobs = {}
    if isinstance(jobs, dict):
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue
            if "permissions" not in job_data or job_data["permissions"] is None:
                continue
            findings.extend(
                _permissions_to_findings(
                    permissions=job_data["permissions"],
                    workflow_file=workflow_file,
                    job_name=str(job_name),
                    oidc_expected=_job_uses_role_to_assume(job_data),
                )
            )

    return findings


def get_dangerous_token_permissions(
    perms: list[GitHubTokenPermission],
) -> list[GitHubTokenPermission]:
    """Return only permissions with risk MEDIUM or higher."""
    return [
        permission
        for permission in perms
        if permission.risk_level >= RiskLevel.MEDIUM
    ]


def summarize_token_risk(perms: list[GitHubTokenPermission]) -> dict:
    """Summarize notable GITHUB_TOKEN permission risks."""
    write_permissions = {
        permission.scope
        for permission in perms
        if permission.access.lower() == "write"
    }

    return {
        "has_write_all": all(
            scope in write_permissions for scope in KNOWN_PERMISSION_SCOPES
        ),
        "has_code_write": "contents" in write_permissions,
        "has_workflow_write": "actions" in write_permissions,
        "has_pr_write": "pull-requests" in write_permissions,
        "has_package_write": "packages" in write_permissions,
        "overall_risk": max(
            (permission.risk_level for permission in perms),
            default=RiskLevel.INFO,
        ),
    }


def _permissions_to_findings(
    permissions: Any,
    workflow_file: str,
    job_name: str,
    oidc_expected: bool,
) -> list[GitHubTokenPermission]:
    if permissions is None or permissions == {}:
        return []

    if isinstance(permissions, str):
        access = permissions.strip().lower()
        if access == "write-all":
            return [
                GitHubTokenPermission(
                    workflow_file=workflow_file,
                    job_name=job_name,
                    scope=scope,
                    access="write",
                    risk_level=RiskLevel.HIGH,
                )
                for scope in KNOWN_PERMISSION_SCOPES
            ]
        if access == "read-all":
            return [
                GitHubTokenPermission(
                    workflow_file=workflow_file,
                    job_name=job_name,
                    scope=scope,
                    access="read",
                    risk_level=RiskLevel.LOW,
                )
                for scope in KNOWN_PERMISSION_SCOPES
            ]
        return []

    if not isinstance(permissions, dict):
        return []

    findings: list[GitHubTokenPermission] = []
    for scope, access in permissions.items():
        normalized_scope = str(scope).strip().lower()
        normalized_access = str(access).strip().lower()
        findings.append(
            GitHubTokenPermission(
                workflow_file=workflow_file,
                job_name=job_name,
                scope=normalized_scope,
                access=normalized_access,
                risk_level=_classify_permission(
                    normalized_scope,
                    normalized_access,
                    oidc_expected,
                ),
            )
        )
    return findings


def _classify_permission(scope: str, access: str, oidc_expected: bool) -> RiskLevel:
    if access != "write":
        return RiskLevel.LOW

    if scope == "id-token" and oidc_expected:
        return RiskLevel.INFO

    if scope in HIGH_WRITE_SCOPES:
        return RiskLevel.HIGH

    if scope in MEDIUM_WRITE_SCOPES:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def _workflow_uses_role_to_assume(workflow_data: dict) -> bool:
    jobs = workflow_data.get("jobs")
    if jobs is None:
        jobs = {}
    if not isinstance(jobs, dict):
        return False
    return any(
        isinstance(job_data, dict) and _job_uses_role_to_assume(job_data)
        for job_data in jobs.values()
    )


def _job_uses_role_to_assume(job_data: dict) -> bool:
    steps = job_data.get("steps", [])
    if not isinstance(steps, list):
        return False

    for step in steps:
        if not isinstance(step, dict):
            continue
        step_with = step.get("with", {})
        if isinstance(step_with, dict) and step_with.get("role-to-assume"):
            return True
    return False
