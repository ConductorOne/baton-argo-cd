package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Argo CD's Account REST API exposes no delete, disable or enable RPC and `Account.enabled` is
// read-only over the API, so account lifecycle changes are applied through the Kubernetes API
// against the `argocd-cm` ConfigMap. See https://github.com/argoproj/argo-cd/issues/4967.
const (
	// argoCDSecretName is the Secret holding local accounts' bcrypt password hashes and token records.
	argoCDSecretName = "argocd-secret"

	// accountKeyPrefix prefixes every local-account key in `argocd-cm` and `argocd-secret`.
	accountKeyPrefix = "accounts."

	accountEnabledSuffix       = ".enabled"
	accountPasswordSuffix      = ".password"
	accountPasswordMtimeSuffix = ".passwordMtime"
	accountTokensSuffix        = ".tokens"

	// adminAccountName is the built-in Argo CD admin account. It is controlled by the top-level
	// `admin.enabled` key rather than by `accounts.*`, so it is never managed here.
	adminAccountName = "admin"

	// accountDisabledValue is the `accounts.<name>.enabled` value that disables an account.
	// Accounts are enabled when the key is absent, so disabling means writing an explicit "false".
	accountDisabledValue = "false"

	jsonPatchOpAdd     = "add"
	jsonPatchOpReplace = "replace"
	jsonPatchOpRemove  = "remove"
)

// accountNameRegexp is the Argo CD local-account name charset, which is narrower than the
// Kubernetes ConfigMap/Secret key charset it is embedded in. Argo CD splits every `accounts.*`
// key on "." and only accepts two-part (`accounts.<name>`) and three-part
// (`accounts.<name>.<suffix>`) keys, so a real account name can never contain a dot. Rejecting
// "." therefore excludes no legitimate account, and it keeps a name from colliding with another
// account's suffix namespace - `accounts.` + "alice.enabled" is alice's enabled flag, not an
// account named "alice.enabled". It also keeps account names out of the JSON Patch path
// unescaped.
var accountNameRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// jsonPatchOperation is a single RFC 6902 operation. Building patches through this type (rather
// than string formatting) keeps account names from breaking out of the JSON document.
type jsonPatchOperation struct {
	Op    string  `json:"op"`
	Path  string  `json:"path"`
	Value *string `json:"value,omitempty"`
}

// marshalJSONPatch serializes operations into a JSON Patch document.
func marshalJSONPatch(ops []jsonPatchOperation) ([]byte, error) {
	patch, err := json.Marshal(ops)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to marshal JSON patch: %w", err)
	}
	return patch, nil
}

// jsonPointerEscape escapes a key for use in a JSON Pointer path (RFC 6901).
func jsonPointerEscape(key string) string {
	return strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

// dataKeyPath returns the JSON Pointer to a key inside a ConfigMap's or Secret's `data` map.
func dataKeyPath(key string) string {
	return "/data/" + jsonPointerEscape(key)
}

// validateAccountName rejects names that cannot be a valid Argo CD local account.
func validateAccountName(username string) error {
	if username == "" {
		return invalidAccountTargetError("account name is required")
	}
	if !accountNameRegexp.MatchString(username) {
		return invalidAccountTargetError(
			"invalid account name %q: Argo CD local account names may only contain alphanumerics, '-' and '_'",
			username,
		)
	}
	return nil
}

// guardManagedAccount validates an account name and refuses to change protected accounts: the
// built-in admin account always, and, for a change that revokes access, the account the connector
// itself authenticates as, since the connector would lock itself out of Argo CD. operation names
// the change ("delete", "disable", ...) for the error message.
func (c *Client) guardManagedAccount(username string, operation string, revokesAccess bool) error {
	if err := validateAccountName(username); err != nil {
		return err
	}

	if strings.EqualFold(username, adminAccountName) {
		return invalidAccountTargetError(
			"refusing to %s the built-in %q account: it is controlled by the top-level 'admin.*' keys, not by 'accounts.*'",
			operation, adminAccountName,
		)
	}

	if revokesAccess && c.username != "" && strings.EqualFold(username, c.username) {
		return invalidAccountTargetError(
			"refusing to %s %q: the connector authenticates as this account and would lose access to Argo CD",
			operation, username,
		)
	}

	return nil
}

// GetAccount fetches a single account from Argo CD. It returns an error wrapping
// ErrAccountNotFound when the account does not exist.
// Endpoint: GET /api/v1/account/{name}.
func (c *Client) GetAccount(ctx context.Context, username string) (*Account, error) {
	if err := validateAccountName(username); err != nil {
		return nil, err
	}

	accountURL, err := c.buildURL(getAccountsURL + "/" + url.PathEscape(username))
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to build account URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accountURL, nil)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to create account request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("argocd-connector: failed to fetch account %q: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, accountNotFoundError("%s", username)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp, fmt.Sprintf("argocd-connector: failed to fetch account %q", username))
	}

	var account Account
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse account JSON: %w", err)
	}

	return &account, nil
}

// RevokeAccountTokens revokes every API token issued to an Argo CD local account. This is the
// only path that revokes a token immediately, so it must run before the account entry is removed
// from `argocd-cm` (the API cannot resolve an account that no longer exists). It returns an error
// wrapping ErrAccountNotFound when Argo CD does not know the account; tokens that are already
// revoked are skipped.
// Endpoint: DELETE /api/v1/account/{name}/token/{id}.
func (c *Client) RevokeAccountTokens(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardManagedAccount(username, "revoke API tokens of", true); err != nil {
		return err
	}

	account, err := c.GetAccount(ctx, username)
	if err != nil {
		return err
	}

	var errs []error
	for _, token := range account.Tokens {
		if token.ID == "" {
			continue
		}
		if err := c.revokeAccountToken(ctx, username, token.ID); err != nil {
			errs = append(errs, err)
			continue
		}
		l.Debug("Revoked Argo CD account token",
			zap.String("account", username),
			zap.String("token_id", token.ID),
		)
	}

	return errors.Join(errs...)
}

// RotateAccountPassword sets a new password for an Argo CD local account. Argo CD records the
// change time and rejects every session and API token issued before it, so rotating the password
// also cuts off existing access. It returns an error wrapping ErrAccountNotFound when Argo CD does
// not know the account.
//
// The password API authenticates the change with the connector's own current password, so
// rotating the account the connector signs in as is refused: it would leave the connector holding
// a stale password.
// Endpoint: PUT /api/v1/account/password.
func (c *Client) RotateAccountPassword(ctx context.Context, username string, password string) error {
	if err := c.guardManagedAccount(username, "rotate the password of", true); err != nil {
		return err
	}

	if _, err := c.GetAccount(ctx, username); err != nil {
		return err
	}

	return c.UpdateUserPassword(ctx, username, password)
}

// revokeAccountToken revokes a single API token. A token Argo CD no longer knows about is treated
// as already revoked.
func (c *Client) revokeAccountToken(ctx context.Context, username string, tokenID string) error {
	tokenURL, err := c.buildURL(fmt.Sprintf("%s/%s/token/%s", getAccountsURL, url.PathEscape(username), url.PathEscape(tokenID)))
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to build token URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, tokenURL, nil)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to create token revocation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return fmt.Errorf("argocd-connector: failed to revoke token %q for account %q: %w", tokenID, username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Already revoked.
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return httpStatusError(resp, fmt.Sprintf("argocd-connector: failed to revoke token %q for account %q", tokenID, username))
	}

	return nil
}

// SetAccountEnabled enables or disables an Argo CD local account through its
// `accounts.<name>.enabled` flag in the `argocd-cm` ConfigMap. Argo CD rejects both password logins
// and API tokens of a disabled account, so the account's stored credentials are left in place and
// re-enabling it restores access as it was.
//
// Disabling writes an explicit "false", adding the key when it is missing and replacing it
// otherwise. Enabling removes the key, since an account is enabled when the key is absent; this
// matches how Argo CD itself persists the flag. An account already in the requested state is left
// untouched. An account that is not defined in `argocd-cm` returns an error wrapping
// ErrAccountNotFound.
func (c *Client) SetAccountEnabled(ctx context.Context, username string, enabled bool) error {
	l := ctxzap.Extract(ctx)

	operation := "disable"
	if enabled {
		operation = "enable"
	}

	if err := c.guardManagedAccount(username, operation, !enabled); err != nil {
		return err
	}

	cm, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(ctx, argoCDConfigMapName, metav1.GetOptions{})
	if err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to fetch ConfigMap '%s' in namespace '%s'",
			argoCDConfigMapName, argocdNamespace,
		))
	}

	accountKey := accountKeyPrefix + username
	enabledKey := accountKey + accountEnabledSuffix

	if _, ok := cm.Data[accountKey]; !ok {
		return accountNotFoundError("%s is not defined in ConfigMap '%s'", username, argoCDConfigMapName)
	}

	currentValue, hasEnabled := cm.Data[enabledKey]
	// Argo CD parses the flag with strconv.ParseBool. An unparsable value is never treated as
	// already being in the requested state, so it gets overwritten.
	current, parseErr := strconv.ParseBool(strings.TrimSpace(currentValue))
	if (!hasEnabled && enabled) || (hasEnabled && parseErr == nil && current == enabled) {
		l.Debug("Argo CD local account is already in the requested state",
			zap.String("account", username),
			zap.Bool("enabled", enabled),
		)
		return nil
	}

	var op jsonPatchOperation
	switch {
	case enabled:
		op = jsonPatchOperation{Op: jsonPatchOpRemove, Path: dataKeyPath(enabledKey)}
	case hasEnabled:
		disabled := accountDisabledValue
		op = jsonPatchOperation{Op: jsonPatchOpReplace, Path: dataKeyPath(enabledKey), Value: &disabled}
	default:
		disabled := accountDisabledValue
		op = jsonPatchOperation{Op: jsonPatchOpAdd, Path: dataKeyPath(enabledKey), Value: &disabled}
	}

	patch, err := marshalJSONPatch([]jsonPatchOperation{op})
	if err != nil {
		return err
	}

	if _, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Patch(
		ctx, argoCDConfigMapName, types.JSONPatchType, patch, metav1.PatchOptions{},
	); err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to %s account %q in ConfigMap '%s'",
			operation, username, argoCDConfigMapName,
		))
	}

	l.Debug("Updated Argo CD local account state",
		zap.String("account", username),
		zap.Bool("enabled", enabled),
	)
	return nil
}

// RemoveAccountRoleGrants removes every role grant (`g, <name>, <role>` line) for an account from
// `policy.csv` in `argocd-rbac-cm`. Without this the grants outlive a deleted account and are
// inherited by any account later created with the same name. Policy (`p`) lines are left
// untouched. An account with no grants is left as is.
func (c *Client) RemoveAccountRoleGrants(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardManagedAccount(username, "remove the role grants of", true); err != nil {
		return err
	}

	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return kubernetesError(err, "argocd-connector: failed to get rbac configmap")
	}

	policyCsv, ok := cm.Data[policyCSVKey]
	if !ok {
		l.Debug("RBAC ConfigMap has no policy, no role grants to remove", zap.String("account", username))
		return nil
	}

	records, err := parsePolicyCSV(policyCsv)
	if err != nil {
		return err
	}

	kept := make([][]string, 0, len(records))
	var removed int
	for _, record := range records {
		if len(record) > 2 && record[0] == policyTypeGrant && record[1] == username {
			removed++
			continue
		}
		kept = append(kept, record)
	}

	if removed == 0 {
		l.Debug("Argo CD local account has no role grants to remove", zap.String("account", username))
		return nil
	}

	if err := c.updateRBACPolicy(ctx, kept, true); err != nil {
		return kubernetesError(err, fmt.Sprintf("argocd-connector: failed to remove role grants of account %q", username))
	}

	l.Debug("Removed Argo CD local account role grants",
		zap.String("account", username),
		zap.Int("removed_grants", removed),
	)
	return nil
}

// DeleteAccount removes an Argo CD local account from the `argocd-cm` ConfigMap, dropping both the
// `accounts.<name>` capabilities entry and its `accounts.<name>.enabled` flag. An account that is
// no longer present is treated as already deleted.
func (c *Client) DeleteAccount(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardManagedAccount(username, "delete", true); err != nil {
		return err
	}

	cm, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(ctx, argoCDConfigMapName, metav1.GetOptions{})
	if err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to fetch ConfigMap '%s' in namespace '%s'",
			argoCDConfigMapName, argocdNamespace,
		))
	}

	accountKey := accountKeyPrefix + username

	var ops []jsonPatchOperation
	for _, key := range []string{accountKey, accountKey + accountEnabledSuffix} {
		if _, ok := cm.Data[key]; ok {
			ops = append(ops, jsonPatchOperation{Op: jsonPatchOpRemove, Path: dataKeyPath(key)})
		}
	}

	if len(ops) == 0 {
		l.Debug("Argo CD local account is not defined in the ConfigMap, nothing to delete",
			zap.String("account", username),
			zap.String("configmap", argoCDConfigMapName),
		)
		return nil
	}

	patch, err := marshalJSONPatch(ops)
	if err != nil {
		return err
	}

	if _, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Patch(
		ctx, argoCDConfigMapName, types.JSONPatchType, patch, metav1.PatchOptions{},
	); err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to delete account %q from ConfigMap '%s'",
			username, argoCDConfigMapName,
		))
	}

	l.Debug("Deleted Argo CD local account", zap.String("account", username))
	return nil
}

// PurgeAccountCredentials removes an account's stored credentials from the `argocd-secret` Secret:
// its bcrypt password hash, the password mtime marker, and its issued token records. Without this
// the secret entries outlive the account and are silently reused if the account name is recreated
// (see https://github.com/argoproj/argo-cd/issues/4102).
func (c *Client) PurgeAccountCredentials(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardManagedAccount(username, "purge stored credentials of", true); err != nil {
		return err
	}

	secret, err := c.k8sClient.CoreV1().Secrets(argocdNamespace).Get(ctx, argoCDSecretName, metav1.GetOptions{})
	if err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to fetch Secret '%s' in namespace '%s'",
			argoCDSecretName, argocdNamespace,
		))
	}

	accountKey := accountKeyPrefix + username

	var ops []jsonPatchOperation
	for _, suffix := range []string{accountPasswordSuffix, accountPasswordMtimeSuffix, accountTokensSuffix} {
		key := accountKey + suffix
		if _, ok := secret.Data[key]; ok {
			ops = append(ops, jsonPatchOperation{Op: jsonPatchOpRemove, Path: dataKeyPath(key)})
		}
	}

	if len(ops) == 0 {
		l.Debug("No stored credentials found for Argo CD local account",
			zap.String("account", username),
			zap.String("secret", argoCDSecretName),
		)
		return nil
	}

	patch, err := marshalJSONPatch(ops)
	if err != nil {
		return err
	}

	if _, err := c.k8sClient.CoreV1().Secrets(argocdNamespace).Patch(
		ctx, argoCDSecretName, types.JSONPatchType, patch, metav1.PatchOptions{},
	); err != nil {
		return kubernetesError(err, fmt.Sprintf(
			"argocd-connector: failed to purge stored credentials for account %q from Secret '%s'",
			username, argoCDSecretName,
		))
	}

	l.Debug("Purged stored credentials for Argo CD local account",
		zap.String("account", username),
		zap.Int("removed_keys", len(ops)),
	)
	return nil
}
