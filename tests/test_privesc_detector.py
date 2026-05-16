"""Tests for AWS IAM privilege escalation path detection."""

from __future__ import annotations

from actionscope.analyzers.privesc_detector import (
    ESCALATION_PATHS,
    PrivescFinding,
    detect_privesc_paths,
    format_privesc_summary,
)
from actionscope.models import IamAction, PolicyFinding, RiskLevel


def action(name: str, resource: str = "*") -> IamAction:
    return IamAction(
        action=name,
        access_level="Permissions management",
        risk_level=RiskLevel.CRITICAL,
        description="test action",
        resource=resource,
    )


def policy(actions: list[IamAction]) -> PolicyFinding:
    return PolicyFinding(
        source_file="policy.json",
        source_type="json_policy",
        role_arn=None,
        actions=actions,
    )


def path_ids(finding: PolicyFinding) -> set[str]:
    return {
        result.path_id
        for result in detect_privesc_paths(finding, finding.source_file)
    }


def test_passrole_wildcard_resource_detected_as_critical() -> None:
    findings = detect_privesc_paths(
        policy([action("iam:PassRole", "*")]),
        "policy.json",
    )

    assert findings[0].path_id == "passrole_wildcard"
    assert findings[0].severity is RiskLevel.CRITICAL


def test_passrole_specific_resource_not_detected() -> None:
    finding = policy(
        [action("iam:PassRole", "arn:aws:iam::123456789012:role/deploy")]
    )

    assert "passrole_wildcard" not in path_ids(finding)


def test_lambda_create_function_detected_when_both_actions_present() -> None:
    finding = policy(
        [
            action("lambda:CreateFunction", "*"),
            action("iam:PassRole", "*"),
        ]
    )

    assert "lambda_create_function" in path_ids(finding)


def test_lambda_create_function_not_detected_with_one_action() -> None:
    finding = policy([action("lambda:CreateFunction", "*")])

    assert "lambda_create_function" not in path_ids(finding)


def test_attach_role_policy_detected() -> None:
    assert "attach_role_policy" in path_ids(policy([action("iam:AttachRolePolicy")]))


def test_create_policy_version_detected() -> None:
    assert "create_policy_version" in path_ids(
        policy([action("iam:CreatePolicyVersion")])
    )


def test_detect_privesc_paths_returns_empty_when_no_paths_match() -> None:
    finding = policy([action("s3:GetObject", "arn:aws:s3:::bucket/*")])

    assert detect_privesc_paths(finding, finding.source_file) == []


def test_detect_privesc_paths_returns_multiple_findings() -> None:
    finding = policy(
        [
            action("iam:PassRole"),
            action("lambda:CreateFunction"),
            action("ec2:RunInstances"),
        ]
    )

    ids = path_ids(finding)
    assert {"passrole_wildcard", "lambda_create_function", "ec2_run_instances"} <= ids


def test_case_insensitive_action_matching() -> None:
    assert "passrole_wildcard" in path_ids(policy([action("IAM:PassRole")]))


def test_format_privesc_summary_non_empty_for_findings() -> None:
    summary = format_privesc_summary(
        [
            PrivescFinding(
                path_id="passrole_wildcard",
                path_name="IAM PassRole + Wildcard Resource",
                description="Can pass roles",
                example_attack="Pass a role to Lambda",
                severity=RiskLevel.CRITICAL,
                matched_actions=["iam:PassRole"],
                source_file="policy.json",
            )
        ]
    )

    assert "privilege escalation" in summary
    assert "IAM PassRole" in summary


def test_format_privesc_summary_empty_for_empty_findings() -> None:
    assert format_privesc_summary([]) == ""


def test_all_eight_paths_are_defined() -> None:
    assert len(ESCALATION_PATHS) == 8
    assert {path["id"] for path in ESCALATION_PATHS} == {
        "passrole_wildcard",
        "create_policy_version",
        "create_access_key",
        "attach_role_policy",
        "update_assume_role",
        "lambda_create_function",
        "ec2_run_instances",
        "cloudformation_create",
    }


def test_policy_finding_privesc_paths_defaults_to_empty_list() -> None:
    finding = PolicyFinding(
        source_file="policy.json",
        source_type="json_policy",
        role_arn=None,
    )

    assert finding.privesc_paths == []


def test_action_star_resource_star_triggers_single_action_paths() -> None:
    ids = path_ids(policy([action("*", "*")]))

    assert {
        "passrole_wildcard",
        "create_policy_version",
        "create_access_key",
        "attach_role_policy",
        "update_assume_role",
    } <= ids


def test_detect_privesc_paths_handles_empty_actions() -> None:
    finding = policy([])

    assert detect_privesc_paths(finding, finding.source_file) == []
