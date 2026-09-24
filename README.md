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

## Account Lifecycle

The connector manages the lifecycle of Argo CD **local accounts** (`accounts.*` entries in
`argocd-cm`). Argo CD's Account API has no delete, disable or enable endpoint and
`Account.enabled` is read-only over the API, so the account entry is changed through the
Kubernetes API (see [argoproj/argo-cd#4967](https://github.com/argoproj/argo-cd/issues/4967)).

| Operation | How it is triggered | Reversible |
|-----------|---------------------|------------|
| Disable | `disable_user` action | Yes, with `enable_user` |
| Enable | `enable_user` action | - |
| Revoke API tokens | `revoke_tokens` action | No |
| Rotate password | Credential rotation (`CAPABILITY_CREDENTIAL_ROTATION`) | No |
| Delete | Account deletion (`CAPABILITY_RESOURCE_DELETE`) | No |

### Disable and enable (actions)

`disable_user` sets `accounts.<name>.enabled: "false"` in `argocd-cm`. Argo CD rejects both
password logins and API tokens of a disabled account, so the account's password and tokens are
left in place. `enable_user` removes the flag again (an account is enabled when the key is
absent), restoring access exactly as it was.

Both actions take one argument, `user_id`: the account name.

```bash
baton-argo-cd --api-url https://argocd.local --username admin --password ... \
  --invoke-action disable_user --invoke-action-args '{"user_id":"alice"}'

baton-argo-cd --api-url https://argocd.local --username admin --password ... \
  --invoke-action enable_user --invoke-action-args '{"user_id":"alice"}'
```

An account that is already in the requested state is reported as success. An account that is not
defined in `argocd-cm` fails with a not-found error.

### Revoke API tokens (action)

`revoke_tokens` revokes every API token issued to the account
(`DELETE /api/v1/account/{name}/token/{id}`). The account, its password and its enabled state are
left unchanged, so it pairs with `disable_user` when a disabled account must not get its old
tokens back on `enable_user`. It takes the same `user_id` argument. An account with no tokens left
is reported as success; an account Argo CD does not know fails with a not-found error.

```bash
baton-argo-cd --api-url https://argocd.local --username admin --password ... \
  --invoke-action revoke_tokens --invoke-action-args '{"user_id":"alice"}'
```

### Rotate password (credential rotation)

The connector supports credential rotation for local accounts with a random password
(`PUT /api/v1/account/password`); C1 stores the new password in a vault, as it does for newly
created accounts. Argo CD rejects every session and API token issued before a password change, so
rotation also cuts off the account's existing access.

### Delete

Deleting an account removes it permanently, in four steps:

1. Revokes every API token issued to the account (`DELETE /api/v1/account/{name}/token/{id}`).
2. Removes every `policy.csv` line in `argocd-rbac-cm` whose subject is the account - its role
   grants (`g, <name>, <role>`) and its direct permissions (`p, <name>, ...`) - so an account
   created later with the same name inherits neither. Only exact name matches are removed. Like
   role revocation, rewriting `policy.csv` normalizes its formatting and drops `#` comment lines.
3. Removes the `accounts.<name>` entry (and its `.enabled` flag) from `argocd-cm`.
4. Purges the account's stored credentials - password hash, password mtime marker, and token
   records - from the `argocd-secret` Secret, so they are not reused if the account name is
   created again (see [argoproj/argo-cd#4102](https://github.com/argoproj/argo-cd/issues/4102)).

Deletion is idempotent: an account that is already gone, or has no RBAC policies or stored
credentials, is reported as successfully deleted.

### Notes and limitations

- The built-in `admin` account cannot be disabled, enabled, rotated, stripped of its tokens or
  deleted by the connector: it is controlled by the top-level `admin.*` keys, not by `accounts.*`.
- The connector refuses to disable, delete, rotate the password of, or revoke the tokens of the
  account it authenticates as, since it would lock itself out of Argo CD. Enabling it is allowed.
- SSO/Dex-managed identities are not local accounts, so there is nothing to manage for them in
  Argo CD itself.
- Argo CD picks up `argocd-cm` changes through its settings watcher. If your deployment has that
  watcher disabled, restart `argocd-server` (`kubectl rollout restart deployment argocd-server -n argocd`)
  for the change to take effect.

### Kubernetes permissions

Account deletion needs `get` and `patch` on the `argocd-secret` Secret in addition to the ConfigMap
permissions used by sync, provisioning and the enable/disable actions. The Secret rule is restricted to `argocd-secret` by
name so the connector cannot read the repository and cluster credentials that also live in the
`argocd` namespace.

**Upgrading an existing deployment:** these Secret permissions are new. Re-apply the role before
account deletion is used — without them the credential-purge step fails with a `403` after the
account has already been deleted, leaving its stored credentials in place.

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
revoke API tokens and to rotate other accounts' passwords.

### Account names

Account names may contain only alphanumerics, `-` and `_`. Argo CD stores each local account as
an `accounts.<name>` key in `argocd-cm` and splits those keys on `.`, so a name containing a dot
is not addressable as an account — `accounts.john.smith` is parsed as a `smith` property of an
account named `john`. Provisioning, deletion, rotation and the account actions all reject such names outright rather than
writing a key Argo CD would silently ignore.

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

This connector supports account creation, deletion and password rotation for users, the
`enable_user`, `disable_user` and `revoke_tokens` actions, and entitlement provisioning for roles.

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
