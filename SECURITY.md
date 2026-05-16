# Security Policy

## Supported Versions

ActionScope is pre-1.0. Security fixes are applied to the latest released
version.

## Reporting a Vulnerability

Please report security issues privately through GitHub Security Advisories:

https://github.com/r12habh/ActionScope/security/advisories/new

If GitHub advisories are unavailable, open a minimal public issue without
exploit details and ask for a private disclosure channel.

## Scope

ActionScope is a read-only analyzer. Static scans read local workflow,
Terraform, and IAM policy files. `--aws-verify` uses read-only IAM APIs:

- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:ListRolePolicies`
- `iam:GetRolePolicy`

ActionScope should never modify cloud resources or repository contents during
analysis.
