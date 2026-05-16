"""Click command-line entrypoint for running ActionScope scans."""

from __future__ import annotations

import os
import sys

import click
from rich.console import Console

from actionscope import __version__
from actionscope.analyzers.risk_engine import build_scan_result
from actionscope.models import PolicyFinding, RiskLevel, ScanResult
from actionscope.parsers.policy_json import scan_policy_files
from actionscope.parsers.terraform import scan_terraform_files
from actionscope.parsers.workflow import scan_workflows
from actionscope.reporters.json_reporter import to_json, write_json
from actionscope.reporters.markdown import to_markdown, write_markdown
from actionscope.reporters.terminal import render_no_aws_found, render_scan_result


@click.group()
@click.version_option(
    __version__,
    "--version",
    prog_name="ActionScope",
    message="%(prog)s v%(version)s",
)
def main() -> None:
    """ActionScope — Map the AWS blast radius of your GitHub Actions
    workflows and AI agent configs."""
    pass


@main.command("version", hidden=True)
def version_command() -> None:
    """Print ActionScope version."""
    click.echo(f"ActionScope v{__version__}")


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--output-format",
    "-f",
    default="terminal",
    type=click.Choice(["terminal", "json", "markdown"]),
    help="Output format",
)
@click.option(
    "--output-file",
    "-o",
    default=None,
    help="Write output to file",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with code 1 if risk >= this level",
)
@click.option(
    "--aws-verify",
    is_flag=True,
    default=False,
    help="Verify permissions via live AWS API calls (requires boto3)",
)
@click.option("--no-color", is_flag=True, default=False)
@click.option("--quiet", "-q", is_flag=True, default=False)
def scan(
    path: str,
    output_format: str,
    output_file: str | None,
    fail_on: str | None,
    aws_verify: bool,
    no_color: bool,
    quiet: bool,
) -> None:
    """Scan a repository for AWS blast radius in GitHub Actions workflows."""

    repo_path = os.path.abspath(path)
    console = Console(no_color=no_color)
    status_console = (
        console
        if output_format == "terminal"
        else Console(no_color=no_color, stderr=True)
    )

    try:
        credential_sources, github_token_perms, workflow_errors = scan_workflows(
            repo_path
        )
    except Exception as exc:
        credential_sources, github_token_perms = [], []
        workflow_errors = [f"Fatal error scanning workflows: {exc}"]

    try:
        json_findings, json_errors = scan_policy_files(repo_path)
    except Exception as exc:
        json_findings, json_errors = [], [str(exc)]

    try:
        tf_findings, tf_errors = scan_terraform_files(repo_path)
    except Exception as exc:
        tf_findings, tf_errors = [], [str(exc)]

    all_policy_findings = json_findings + tf_findings
    all_errors = workflow_errors + json_errors + tf_errors

    if aws_verify:
        try:
            from actionscope.verifiers.aws_verifier import (
                check_boto3_available,
                extract_role_name_from_arn,
                verify_all_credential_sources,
            )

            check_boto3_available()
            status_console.print("[dim]Running AWS verification...[/dim]")
            aws_findings, aws_errors = verify_all_credential_sources(
                credential_sources
            )
            verified_role_names = {
                role_name.lower()
                for finding in aws_findings
                if finding.role_arn
                for role_name in [extract_role_name_from_arn(finding.role_arn)]
                if role_name
            }
            verified_role_arns = {
                finding.role_arn for finding in aws_findings if finding.role_arn
            }
            static_only = [
                finding
                for finding in all_policy_findings
                if not _finding_matches_verified_role(
                    finding,
                    verified_role_arns,
                    verified_role_names,
                )
            ]
            all_policy_findings = static_only + aws_findings
            all_errors.extend(aws_errors)
        except RuntimeError as exc:
            status_console.print(f"[red]AWS verification failed: {exc}[/red]")
            all_errors.append(f"AWS verification failed: {exc}")

    try:
        result = build_scan_result(
            repo_path=repo_path,
            credential_sources=credential_sources,
            github_token_perms=github_token_perms,
            policy_findings=all_policy_findings,
            errors=all_errors,
        )
    except Exception as exc:
        result = ScanResult(
            scan_path=repo_path,
            workflow_count=0,
            credential_sources=credential_sources,
            github_token_permissions=github_token_perms,
            policy_findings=all_policy_findings,
            errors=all_errors + [f"Could not correlate scan results: {exc}"],
        )

    # Step 5: Handle case of no AWS usage
    if not credential_sources:
        if output_format == "terminal":
            if not quiet:
                render_no_aws_found(console)
            if output_file:
                write_markdown(result, output_file)
        elif output_format == "json":
            output = to_json(result)
            if output_file:
                write_json(result, output_file)
            else:
                print(output)
        elif output_format == "markdown":
            md = to_markdown(result)
            if output_file:
                write_markdown(result, output_file)
            else:
                print(md)
        _exit_with_fail_on(result, fail_on)

    # Step 6: Render output
    if output_format == "terminal":
        if not quiet:
            render_scan_result(result, console)
        if output_file:
            write_markdown(result, output_file)
    elif output_format == "json":
        output = to_json(result)
        if output_file:
            write_json(result, output_file)
        else:
            print(output)
    elif output_format == "markdown":
        md = to_markdown(result)
        if output_file:
            write_markdown(result, output_file)
        else:
            print(md)

    _exit_with_fail_on(result, fail_on)


def _exit_with_fail_on(result: ScanResult, fail_on: str | None) -> None:
    if fail_on:
        fail_risk = RiskLevel(fail_on)
        if result.overall_risk >= fail_risk:
            sys.exit(1)
    sys.exit(0)


def _finding_matches_verified_role(
    finding: PolicyFinding,
    verified_role_arns: set[str],
    verified_role_names: set[str],
) -> bool:
    if finding.role_arn in verified_role_arns:
        return True

    if finding.role_arn:
        role_tail = finding.role_arn.strip("/").rsplit("/", 1)[-1].lower()
        if role_tail in verified_role_names:
            return True

    source_file = finding.source_file.lower()
    if any(role_name in source_file for role_name in verified_role_names):
        return True

    try:
        with open(finding.source_file, encoding="utf-8") as source:
            source_text = source.read().lower()
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError) as exc:
        print(
            f"Warning: could not read policy finding source {finding.source_file}: "
            f"{exc}",
            file=sys.stderr,
        )
        return False

    return any(role_name in source_text for role_name in verified_role_names)
