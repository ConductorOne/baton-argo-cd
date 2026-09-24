While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

   > The connector syncs ArgoCD users and roles.

2. Can the connector provision any resources? If so, which ones?
   > Yes, the connector can provision user accounts and manage role assignments (entitlements) for users.
   >
   > It can also delete ArgoCD local accounts. Deletion is permanent: it revokes the account's issued
   > API tokens, removes its role grants from `argocd-rbac-cm`, removes its `accounts.<name>` entry
   > from `argocd-cm`, and purges its stored credentials from `argocd-secret`.
   >
   > For reversible deactivation, the connector offers the `disable_user` and `enable_user` actions.
   > `disable_user` sets `accounts.<name>.enabled: "false"` in `argocd-cm`; the account keeps its
   > password and API tokens, which ArgoCD rejects while it is disabled. `enable_user` removes the flag
   > again, restoring access as it was. Prefer `disable_user` for access you may need to restore, and
   > deletion to remove the account for good.
   >
   > The `revoke_tokens` action revokes an account's API tokens without changing anything else, for
   > example alongside `disable_user` so a later `enable_user` does not bring old tokens back.
   >
   > The connector also supports credential rotation: it sets a new random password for a local
   > account, which C1 stores in a vault. ArgoCD rejects every session and API token issued before a
   > password change.
   >
   > The built-in `admin` account cannot be disabled, enabled, rotated, stripped of its tokens or
   > deleted, and SSO/Dex identities are not local accounts so there is nothing to manage for them.
   > The connector also refuses to disable, delete, rotate or revoke the tokens of the account it
   > authenticates as, since it would lock itself out.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

   > The connector requires the following to connect to your ArgoCD instance:
   >
   > - **API URL**: The URL for your ArgoCD API server.
   > - **Username**: The username for a user with administrative privileges in ArgoCD.
   > - **Password**: The password for the administrative user.
   > - **Kubeconfig**: The kubeconfig path or file (optional if deployed alongside ArgoCD).

2. For each item in the list above:

   - How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.

     > - **API URL**: This is the URL you use to access your ArgoCD UI.
     > - **Username/Password**: You can use the initial built-in `admin` user, or create a dedicated local user for the integration. For security, it's recommended to create a dedicated user with the necessary permissions. You can find more information in the [ArgoCD User Management documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/user-management/).
     > - **Kubeconfig**: This is the config file to connect to the cluster where Argo-CD is running.
     >   1. **Provided kubeconfig file**: If a kubeconfig file is provided through the connector configuration, it will be used to connect to the cluster.
     >   2. **In-cluster configuration**: If the connector is deployed in the same Kubernetes cluster as ArgoCD (e.g., in the `argocd` namespace), it will automatically use the in-cluster configuration from the pod's service account. No kubeconfig file is needed in this case. If one is provided it will take precedence over in-cluster.
     >   3. **Default kubeconfig location**: If no kubeconfig is provided and in-cluster config is not available, the connector will attempt to use the default kubeconfig file at `~/.kube/config`.
     >
     >   To create or obtain a kubeconfig file, you can:
     >   - Use `kubectl config view` to view your current kubeconfig
     >   - Export your kubeconfig with `kubectl config view --raw` if you need to share it

   - Does the credential need any specific scopes or permissions? If so, list them here.
     > The user account provided needs to have permissions to:
     >
     > - List and get users and roles.

   * - Create new user accounts.
   * - Delete local user accounts and revoke their API tokens.
   * - Disable and enable local user accounts, and revoke their API tokens.
   * - Rotate local user account passwords.
   * - Manage role assignments for users (updating user-role mappings).
       > The built-in `admin` role has all the necessary permissions. If creating a custom role, ensure it has the appropriate permissions for `users` and `roles` resources as described in the [ArgoCD RBAC documentation](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/).

   - If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

     > Yes, the permissions differ:
     >
     > - **Sync (Read-only)**: Requires permissions to `get` and `list` users and roles.
     > - **Provision (Read-Write)**: Requires all read permissions, plus permissions to `create` users and `update` user-role assignments.
     > - **Disable / enable actions (Read-Write)**: Require Kubernetes `get`/`patch` on the `argocd-cm` ConfigMap, already needed for provisioning.
     > - **Revoke tokens action and password rotation (Read-Write)**: Require `accounts, update` in ArgoCD RBAC.
     > - **Delete (Read-Write)**: Requires all provision permissions, plus `accounts, update` in ArgoCD RBAC (to revoke API tokens) and Kubernetes `get`/`patch` on the `argocd-secret` Secret (to purge stored credentials).

   - What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)
     > To create a user with the necessary permissions in ArgoCD, you need to be an administrator of the ArgoCD instance. This is typically done by logging in as the `admin` user or another user with equivalent administrative privileges.


## Kubernetes Deployment (In-Cluster Configuration)

When deploying the connector in the same Kubernetes cluster and namespace as ArgoCD, the connector can use in-cluster configuration, eliminating the need for a kubeconfig file. This is the recommended approach for production deployments.

### Prerequisites

- ArgoCD running in the `argocd` namespace (or your target namespace)
- `kubectl` configured to access your Kubernetes cluster
- Cluster admin permissions to create ServiceAccounts, Roles, and RoleBindings

### Deployment Steps

1. **Create a ServiceAccount**

   The connector needs a ServiceAccount to authenticate with the Kubernetes API. Create a ServiceAccount in the `argocd` namespace:

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: baton-argo-cd
     namespace: argocd
   ```

   Apply with:
   ```bash
   kubectl apply -f serviceaccount.yaml
   ```

2. **Create a Role with Required Permissions**

   The connector needs permissions to read and modify ArgoCD ConfigMaps, and to read and patch the ArgoCD Secret. Create a Role that grants access to the following objects:
   - `argocd-rbac-cm` ConfigMap: Contains RBAC policies and role grants (needs read and write access)
   - `argocd-cm` ConfigMap: Contains ArgoCD configuration including user accounts (needs write access for provisioning, deprovisioning and the enable/disable actions)
   - `argocd-secret` Secret: Contains local accounts' password hashes and API token records (needs read and write access for account deletion)

   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: baton-argo-cd
     namespace: argocd
   rules:
     - apiGroups: [""]
       resources: ["configmaps"]
       verbs: ["get", "list", "patch", "update"]
     - apiGroups: [""]
       resources: ["secrets"]
       resourceNames: ["argocd-secret"]
       verbs: ["get", "patch"]
   ```

   **Required Permissions Explained:**
   - `get`: Read individual ConfigMaps (required to read `argocd-rbac-cm` and `argocd-cm`)
   - `list`: List ConfigMaps in the namespace (required to discover and access the ConfigMaps)
   - `patch`: Partially update ConfigMaps (used to modify RBAC policies and user accounts)
   - `update`: Fully update ConfigMaps (used as an alternative to patch for modifying ConfigMaps)
   - `get`/`patch` on `secrets`: Read and purge a deleted account's stored credentials (password hash and API token records) in `argocd-secret`. Only needed for account deletion.

   Apply with:
   ```bash
   kubectl apply -f role.yaml
   ```

3. **Create a RoleBinding**

   Bind the Role to the ServiceAccount so the connector can use the permissions:

   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata:
     name: baton-argo-cd
     namespace: argocd
   roleRef:
     apiGroup: rbac.authorization.k8s.io
     kind: Role
     name: baton-argo-cd
   subjects:
     - kind: ServiceAccount
       name: baton-argo-cd
       namespace: argocd
   ```

   Apply with:
   ```bash
   kubectl apply -f rolebinding.yaml
   ```

4. **Create a Secret with ArgoCD Credentials**

   Create a Kubernetes Secret containing your ArgoCD username and password:

   ```bash
   kubectl create secret generic baton-argo-cd-secret \
     --from-literal=username=admin \
     --from-literal=password=your-argocd-password \
     -n argocd
   ```

   Or create from a YAML file:
   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: baton-argo-cd-secret
     namespace: argocd
   type: Opaque
   stringData:
     username: admin
     password: your-argocd-password
   ```

5. **Deploy the Connector**

   Deploy the connector with a Deployment that references the ServiceAccount and uses the secret for credentials. The deployment should:
   - Use the `baton-argo-cd` ServiceAccount
   - Set `BATON_API_URL` to the internal ArgoCD service URL (e.g., `http://argocd-server.argocd.svc.cluster.local`)
   - Reference the secret for `BATON_USERNAME` and `BATON_PASSWORD`
   - **Do not set `BATON_KUBECONFIG`** - this allows the connector to use in-cluster configuration automatically

   Example deployment snippet:
   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: baton-argo-cd
     namespace: argocd
   spec:
     template:
       spec:
         serviceAccountName: baton-argo-cd
         containers:
           - name: baton-argo-cd
             env:
               - name: BATON_API_URL
                 value: "http://argocd-server.argocd.svc.cluster.local"
               - name: BATON_USERNAME
                 valueFrom:
                   secretKeyRef:
                     name: baton-argo-cd-secret
                     key: username
               - name: BATON_PASSWORD
                 valueFrom:
                   secretKeyRef:
                     name: baton-argo-cd-secret
                     key: password
   ```

### Verifying Permissions

After deployment, verify that the ServiceAccount has the correct permissions:

```bash
# Check if the ServiceAccount can read the RBAC ConfigMap
kubectl auth can-i get configmaps/argocd-rbac-cm -n argocd --as=system:serviceaccount:argocd:baton-argo-cd

# Check if the ServiceAccount can update the RBAC ConfigMap
kubectl auth can-i patch configmaps/argocd-rbac-cm -n argocd --as=system:serviceaccount:argocd:baton-argo-cd

# Check if the ServiceAccount can update the ArgoCD ConfigMap
kubectl auth can-i patch configmaps/argocd-cm -n argocd --as=system:serviceaccount:argocd:baton-argo-cd

# Check if the ServiceAccount can read and update the ArgoCD Secret (account deletion)
kubectl auth can-i get secrets/argocd-secret -n argocd --as=system:serviceaccount:argocd:baton-argo-cd
kubectl auth can-i patch secrets/argocd-secret -n argocd --as=system:serviceaccount:argocd:baton-argo-cd
```

All commands should return `yes` if the permissions are correctly configured.

### Benefits of In-Cluster Deployment

- **No kubeconfig required**: The connector automatically uses the ServiceAccount's credentials
- **More secure**: No need to manage and rotate kubeconfig files
- **Simpler configuration**: Fewer configuration parameters to manage
- **Better for production**: Follows Kubernetes best practices for service-to-service authentication