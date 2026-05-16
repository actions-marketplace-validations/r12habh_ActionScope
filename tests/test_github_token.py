"""Tests for the GITHUB_TOKEN scope analyzer."""

from actionscope.analyzers.github_token import (
    KNOWN_PERMISSION_SCOPES,
    analyze_workflow_permissions,
    get_dangerous_token_permissions,
    summarize_token_risk,
)
from actionscope.models import RiskLevel


def test_write_all_at_workflow_level_has_high_overall_risk() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "write-all"},
        ".github/workflows/ci.yml",
    )

    summary = summarize_token_risk(perms)

    assert summary["has_write_all"] is True
    assert summary["overall_risk"] is RiskLevel.HIGH


def test_write_all_expands_known_scopes_at_workflow_level() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "write-all"},
        ".github/workflows/ci.yml",
    )

    assert {permission.scope for permission in perms} == set(KNOWN_PERMISSION_SCOPES)
    assert {permission.job_name for permission in perms} == {""}
    assert {permission.risk_level for permission in perms} == {RiskLevel.HIGH}


def test_read_all_expands_to_low_risk_permissions() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": "read-all"},
        ".github/workflows/ci.yml",
    )

    assert len(perms) == len(KNOWN_PERMISSION_SCOPES)
    assert {permission.risk_level for permission in perms} == {RiskLevel.LOW}


def test_contents_write_is_medium() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"contents": "write"}},
        ".github/workflows/ci.yml",
    )

    assert perms[0].scope == "contents"
    assert perms[0].risk_level is RiskLevel.MEDIUM


def test_pull_requests_write_is_high() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"pull-requests": "write"}},
        ".github/workflows/ci.yml",
    )

    assert perms[0].scope == "pull-requests"
    assert perms[0].risk_level is RiskLevel.HIGH


def test_id_token_write_is_noted_as_high_without_role_to_assume() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"id-token": "write", "contents": "read"}},
        ".github/workflows/deploy.yml",
    )

    by_scope = {permission.scope: permission for permission in perms}

    assert by_scope["id-token"].risk_level is RiskLevel.HIGH
    assert by_scope["contents"].risk_level is RiskLevel.LOW


def test_id_token_write_with_role_to_assume_is_info() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"id-token": "write"},
            "jobs": {
                "deploy": {
                    "steps": [
                        {
                            "uses": "aws-actions/configure-aws-credentials@v4",
                            "with": {
                                "role-to-assume": (
                                    "arn:aws:iam::123456789012:role/ci-deploy"
                                )
                            },
                        }
                    ]
                }
            },
        },
        ".github/workflows/deploy.yml",
    )

    assert perms[0].risk_level is RiskLevel.INFO


def test_no_permissions_block_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"jobs": {"test": {"steps": []}}},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_job_level_override_captured_with_job_name() -> None:
    perms = analyze_workflow_permissions(
        {"jobs": {"deploy": {"permissions": {"contents": "read"}}}},
        ".github/workflows/deploy.yml",
    )

    assert len(perms) == 1
    assert perms[0].job_name == "deploy"
    assert perms[0].scope == "contents"


def test_job_override_includes_workflow_and_job_permissions() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {"contents": "write"},
            "jobs": {
                "deploy": {
                    "permissions": {"contents": "read"},
                }
            },
        },
        ".github/workflows/deploy.yml",
    )

    assert [(permission.job_name, permission.access) for permission in perms] == [
        ("", "write"),
        ("deploy", "read"),
    ]


def test_summarize_token_risk_has_pr_write_for_pull_requests_write() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {"pull-requests": "write"}},
        ".github/workflows/ci.yml",
    )

    assert summarize_token_risk(perms)["has_pr_write"] is True


def test_permissions_null_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": None},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_permissions_empty_dict_returns_empty_list() -> None:
    perms = analyze_workflow_permissions(
        {"permissions": {}},
        ".github/workflows/ci.yml",
    )

    assert perms == []


def test_get_dangerous_token_permissions_returns_medium_or_higher() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {
                "contents": "write",
                "pull-requests": "write",
                "issues": "read",
            }
        },
        ".github/workflows/ci.yml",
    )

    dangerous = get_dangerous_token_permissions(perms)

    assert [permission.scope for permission in dangerous] == [
        "contents",
        "pull-requests",
    ]


def test_summarize_token_risk_sets_write_flags() -> None:
    perms = analyze_workflow_permissions(
        {
            "permissions": {
                "actions": "write",
                "contents": "write",
                "packages": "write",
            }
        },
        ".github/workflows/release.yml",
    )

    summary = summarize_token_risk(perms)

    assert summary["has_code_write"] is True
    assert summary["has_workflow_write"] is True
    assert summary["has_package_write"] is True
    assert summary["overall_risk"] is RiskLevel.HIGH
