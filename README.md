![Baton Logo](./baton-logo.png)

# `baton-argo-cd` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-argo-cd.svg)](https://pkg.go.dev/github.com/conductorone/baton-argo-cd) ![main ci](https://github.com/conductorone/baton-argo-cd/actions/workflows/main.yaml/badge.svg)

`baton-argo-cd` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Prerequisites

## RBAC Role Requirements

To grant roles to users, role definitions must exist in the `argocd-rbac-cm` ConfigMap **before** assignment.

**Built-in roles** (always available):
- `admin` - Full administrative access
- `readonly` - Read-only access to all resources

**Custom roles** must be defined before granting:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.csv: |
    # Define custom roles FIRST (policy definitions)
    p, role:developers, applications, get, default/*, allow
    p, role:operators, applications, *, */*, allow

    # Then grants can be added (manually or via baton)
    g, alice, role:developers
```

**Policy line format**: `p, role:<name>, resource, action, object, effect`

See [ArgoCD RBAC documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/) for details.

## Account Deprovisioning

The connector deprovisions Argo CD **local accounts** (`accounts.*` entries in `argocd-cm`).
Argo CD's Account API has no delete or disable endpoint and `Account.enabled` is read-only over
the API, so the account entry is changed through the Kubernetes API
(see [argoproj/argo-cd#4967](https://github.com/argoproj/argo-cd/issues/4967)).

Deprovisioning an account performs three steps:

1. Revokes every API token issued to the account (`DELETE /api/v1/account/{name}/token/{id}`).
2. Disables or deletes the account entry in `argocd-cm`, per `--deprovision-mode`.
3. Purges the account's stored credentials - password hash, password mtime marker, and token
   records - from the `argocd-secret` Secret, so no residual access path survives the account
   (see [argoproj/argo-cd#4102](https://github.com/argoproj/argo-cd/issues/4102)).

`--deprovision-mode` controls step 2:

| Mode | Behavior |
|------|----------|
| `disable` (default) | Sets `accounts.<name>.enabled: "false"`. Reversible and preserves the account's audit identity. Accounts are enabled when the key is absent, so it is added when missing. |
| `delete` | Removes the `accounts.<name>` entry (and its `.enabled` flag) from `argocd-cm`. |

```bash
# Default: disable the account, keeping the entry for audit purposes
baton-argo-cd --api-url https://argocd.local --username admin --password ...   --deprovision-mode disable

# Remove the account entry outright
baton-argo-cd --api-url https://argocd.local --username admin --password ...   --deprovision-mode delete
```

Notes and limitations:

- The built-in `admin` account is **not** deprovisionable: it is controlled by the top-level
  `admin.enabled` key in `argocd-cm`, not by `accounts.*`. Deprovisioning it is rejected.
- SSO/Dex-managed identities are not local accounts, so there is nothing to deprovision for them
  in Argo CD itself.
- Because credentials are purged in both modes, re-enabling a disabled account requires setting a
  new password.
- Deprovisioning is idempotent: an account that is already disabled, already deleted, or has no
  stored credentials is reported as successfully deprovisioned.
- Argo CD picks up `argocd-cm` changes through its settings watcher. If your deployment has that
  watcher disabled, restart `argocd-server` (`kubectl rollout restart deployment argocd-server -n argocd`)
  for the change to take effect.

### Kubernetes permissions

Deprovisioning needs `get` and `patch` on the `argocd-secret` Secret in addition to the ConfigMap
permissions used by sync and provisioning. The Secret rule is restricted to `argocd-secret` by
name so the connector cannot read the repository and cluster credentials that also live in the
`argocd` namespace.

**Upgrading an existing deployment:** these Secret permissions are new. Re-apply the role before
deprovisioning is used — without them the credential-purge step fails with a `403` after the
account has already been disabled or deleted, leaving its stored credentials in place.

```yaml
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["argocd-secret"]
    verbs: ["get", "patch"]
```

The Argo CD account used by the connector also needs the `accounts, update` RBAC permission to
revoke API tokens.

## TLS Configuration

When connecting to ArgoCD instances with self-signed certificates, you have two options:

**For development/testing** (insecure):
```bash
baton-argo-cd --insecure-skip-verify true --api-url https://argocd.local ...
```

**For production** (secure with custom CA):
```bash
baton-argo-cd --ca-cert-path /path/to/ca.crt --api-url https://argocd.local ...
```

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-argo-cd
baton-argo-cd
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_DOMAIN_URL=domain_url -e BATON_API_KEY=apiKey -e BATON_USERNAME=username ghcr.io/conductorone/baton-argo-cd:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-argo-cd/cmd/baton-argo-cd@main

baton-argo-cd

baton resources
```

# Data Model

`baton-argo-cd` will pull down information about the following resources from ArgoCD:

- Users
- Roles

This connector supports account provisioning and deprovisioning for users, and entitlement
provisioning for roles.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-argo-cd` Command Line Usage

```
baton-argo-cd

Usage:
  baton-argo-cd [flags]
  baton-argo-cd [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --username  string             The username used to authenticate with Argo CD
      --password  string             The password used to authenticate with Argo CD
      --api-url   string             The API URL
      --deprovision-mode string      How to deprovision a local account: disable or delete (default "disable")
      --client-id string             The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string         The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                  The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                         help for baton-argo-cd
      --log-format string            The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string             The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                 If this connector supports provisioning, this must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --ticketing                    This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                      version for baton-argo-cd

Use "baton-argo-cd [command] --help" for more information about a command.
```
