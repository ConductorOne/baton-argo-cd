While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

   > The connector syncs ArgoCD users and roles.

2. Can the connector provision any resources? If so, which ones?
   > Yes, the connector can provision user accounts and manage role assignments (entitlements) for users.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

   > The connector requires the following to connect to your ArgoCD instance:
   >
   > - **API URL**: The URL for your ArgoCD API server.
   > - **Username**: The username for a user with administrative privileges in ArgoCD.
   > - **Password**: The password for the administrative user.

2. For each item in the list above:

   - How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.

     > - **API URL**: This is the URL you use to access your ArgoCD UI.
     > - **Username/Password**: You can use the initial built-in `admin` user, or create a dedicated local user for the integration. For security, it's recommended to create a dedicated user with the necessary permissions. You can find more information in the [ArgoCD User Management documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/user-management/).

   - Does the credential need any specific scopes or permissions? If so, list them here.
     > The user account provided needs to have permissions to:
     >
     > - List and get users and roles.

   * - Create new user accounts.
   * - Manage role assignments for users (updating user-role mappings).
       > The built-in `admin` role has all the necessary permissions. If creating a custom role, ensure it has the appropriate permissions for `users` and `roles` resources as described in the [ArgoCD RBAC documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/).

   - If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

     > Yes, the permissions differ:
     >
     > - **Sync (Read-only)**: Requires permissions to `get` and `list` users and roles.
     > - **Provision (Read-Write)**: Requires all read permissions, plus permissions to `create` users and `update` user-role assignments.

   - What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)
     > To create a user with the necessary permissions in ArgoCD, you need to be an administrator of the ArgoCD instance. This is typically done by logging in as the `admin` user or another user with equivalent administrative privileges.
