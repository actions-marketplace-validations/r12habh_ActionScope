"""Smoke coverage for the Rich terminal reporter."""

import io

from rich.console import Console

from actionscope.models import (
    AwsCredentialSource,
    GitHubTokenPermission,
    IamAction,
    PolicyFinding,
    RiskLevel,
    ScanResult,
    WorkflowCredentialBinding,
)
from actionscope.reporters.terminal import render_scan_result


def test_render_scan_result_smoke_full_scan_result() -> None:
    credential = AwsCredentialSource(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        step_name="Configure AWS credentials",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        uses_access_keys=False,
        uses_oidc=True,
        aws_region="us-east-1",
    )

    matched_actions = [
        IamAction(
            "iam:PassRole",
            "Perm Mgmt",
            RiskLevel.CRITICAL,
            "Pass role",
            "*",
        ),
        IamAction(
            "ec2:TerminateInstances",
            "Write",
            RiskLevel.HIGH,
            "Terminate",
            "*",
        ),
        IamAction(
            "s3:GetObject",
            "Read",
            RiskLevel.LOW,
            "Read object",
            "*",
        ),
    ]

    matched_policy = PolicyFinding(
        source_file="terraform/deploy.tf",
        source_type="terraform",
        role_arn="arn:aws:iam::123456789012:role/github-deploy-role",
        actions=matched_actions,
        has_passrole=True,
        overall_risk=RiskLevel.CRITICAL,
    )

    unmatched_policy = PolicyFinding(
        source_file="terraform/iam.tf",
        source_type="terraform",
        role_arn=None,
        actions=[
            IamAction(
                "iam:PassRole",
                "Perm Mgmt",
                RiskLevel.CRITICAL,
                "",
                "*",
            ),
        ],
        has_passrole=True,
        overall_risk=RiskLevel.CRITICAL,
    )

    binding = WorkflowCredentialBinding(
        credential_source=credential,
        policy_finding=matched_policy,
        policy_source="terraform",
    )

    github_perm = GitHubTokenPermission(
        workflow_file=".github/workflows/deploy.yml",
        job_name="deploy",
        scope="contents",
        access="write",
        risk_level=RiskLevel.MEDIUM,
    )

    result = ScanResult(
        scan_path="/path/to/repo",
        workflow_count=3,
        credential_sources=[credential],
        github_token_permissions=[github_perm],
        policy_findings=[matched_policy, unmatched_policy],
        bindings=[binding],
        errors=["Could not parse .github/workflows/broken.yml: yaml error"],
    )

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120)

    render_scan_result(result, console=console)

    output = buf.getvalue()
    assert "ActionScope" in output
    assert "CRITICAL" in output
