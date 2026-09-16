package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// DeprovisionMode selects what happens to an Argo CD local account when it is deprovisioned.
//
// Argo CD's Account REST API exposes no delete or disable RPC and `Account.enabled` is read-only
// over the API, so both modes are applied through the Kubernetes API against the `argocd-cm`
// ConfigMap. See https://github.com/argoproj/argo-cd/issues/4967.
type DeprovisionMode string

const (
	// DeprovisionModeDisable keeps the account entry and sets `accounts.<name>.enabled` to "false".
	// It is reversible and preserves the account's audit identity.
	DeprovisionModeDisable DeprovisionMode = "disable"
	// DeprovisionModeDelete removes the `accounts.<name>` entry from `argocd-cm` outright.
	DeprovisionModeDelete DeprovisionMode = "delete"
)

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
	// `admin.enabled` key rather than by `accounts.*`, so it is never deprovisionable here.
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

// ErrAccountNotFound is returned when Argo CD does not know the requested account.
var ErrAccountNotFound = errors.New("argocd-connector: account not found")

// ParseDeprovisionMode normalizes a configured deprovision mode. An empty value selects the
// default, `disable`.
//
// The config field carries an exact-match `in` rule, so a non-canonical spelling is rejected at
// config validation before it reaches here. The normalization below is a backstop for callers
// that construct a mode without going through field validation, not a documented tolerance.
func ParseDeprovisionMode(value string) (DeprovisionMode, error) {
	switch mode := DeprovisionMode(strings.ToLower(strings.TrimSpace(value))); mode {
	case "":
		return DeprovisionModeDisable, nil
	case DeprovisionModeDisable, DeprovisionModeDelete:
		return mode, nil
	default:
		return "", fmt.Errorf(
			"argocd-connector: unsupported deprovision mode %q: must be %q or %q",
			value, DeprovisionModeDisable, DeprovisionModeDelete,
		)
	}
}

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
		return errors.New("argocd-connector: account name is required")
	}
	if !accountNameRegexp.MatchString(username) {
		return fmt.Errorf(
			"argocd-connector: invalid account name %q: Argo CD local account names may only contain "+
				"alphanumerics, '-' and '_'",
			username,
		)
	}
	return nil
}

// guardDeprovisionTarget validates an account name and refuses to deprovision protected accounts.
func (c *Client) guardDeprovisionTarget(ctx context.Context, username string) error {
	if err := validateAccountName(username); err != nil {
		return err
	}

	if strings.EqualFold(username, adminAccountName) {
		return fmt.Errorf(
			"argocd-connector: refusing to deprovision the built-in %q account: it is controlled by the "+
				"top-level 'admin.enabled' key in argocd-cm, not by 'accounts.*'",
			adminAccountName,
		)
	}

	if c.username != "" && strings.EqualFold(username, c.username) {
		ctxzap.Extract(ctx).Warn(
			"deprovisioning the Argo CD account the connector authenticates as; the connector will lose access",
			zap.String("account", username),
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
		return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, username)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"argocd-connector: failed to fetch account %q with status %d: %s",
			username, resp.StatusCode, string(bodyBytes),
		)
	}

	var account Account
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse account JSON: %w", err)
	}

	return &account, nil
}

// RevokeAccountTokens revokes every API token issued to an Argo CD local account. This is the
// only path that revokes a token immediately, so it must run before the account entry is removed
// from `argocd-cm` (the API cannot resolve an account that no longer exists).
// Endpoint: DELETE /api/v1/account/{name}/token/{id}.
func (c *Client) RevokeAccountTokens(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardDeprovisionTarget(ctx, username); err != nil {
		return err
	}

	account, err := c.GetAccount(ctx, username)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			// Already deprovisioned: there is nothing left to revoke.
			l.Debug("Argo CD account not found, no tokens to revoke", zap.String("account", username))
			return nil
		}
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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(
			"argocd-connector: failed to revoke token %q for account %q with status %d: %s",
			tokenID, username, resp.StatusCode, string(bodyBytes),
		)
	}

	return nil
}

// DisableAccount disables an Argo CD local account by setting `accounts.<name>.enabled` to "false"
// in the `argocd-cm` ConfigMap. Accounts are enabled when that key is absent, so the key is added
// when it is missing and replaced otherwise. An account that is not defined in `argocd-cm`, or that
// is already disabled, is treated as already deprovisioned.
func (c *Client) DisableAccount(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardDeprovisionTarget(ctx, username); err != nil {
		return err
	}

	cm, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(ctx, argoCDConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf(
			"argocd-connector: failed to fetch ConfigMap '%s' in namespace '%s': %w",
			argoCDConfigMapName, argocdNamespace, err,
		)
	}

	accountKey := accountKeyPrefix + username
	enabledKey := accountKey + accountEnabledSuffix

	_, hasAccount := cm.Data[accountKey]
	currentEnabled, hasEnabled := cm.Data[enabledKey]

	if !hasAccount && !hasEnabled {
		l.Debug("Argo CD local account is not defined in the ConfigMap, nothing to disable",
			zap.String("account", username),
			zap.String("configmap", argoCDConfigMapName),
		)
		return nil
	}

	if hasEnabled && strings.EqualFold(strings.TrimSpace(currentEnabled), accountDisabledValue) {
		l.Debug("Argo CD local account is already disabled", zap.String("account", username))
		return nil
	}

	op := jsonPatchOpAdd
	if hasEnabled {
		op = jsonPatchOpReplace
	}

	disabled := accountDisabledValue
	patch, err := marshalJSONPatch([]jsonPatchOperation{{
		Op:    op,
		Path:  dataKeyPath(enabledKey),
		Value: &disabled,
	}})
	if err != nil {
		return err
	}

	if _, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Patch(
		ctx, argoCDConfigMapName, types.JSONPatchType, patch, metav1.PatchOptions{},
	); err != nil {
		return fmt.Errorf(
			"argocd-connector: failed to disable account %q in ConfigMap '%s': %w",
			username, argoCDConfigMapName, err,
		)
	}

	l.Debug("Disabled Argo CD local account", zap.String("account", username))
	return nil
}

// DeleteAccount removes an Argo CD local account from the `argocd-cm` ConfigMap, dropping both the
// `accounts.<name>` capabilities entry and its `accounts.<name>.enabled` flag. An account that is
// no longer present is treated as already deprovisioned.
func (c *Client) DeleteAccount(ctx context.Context, username string) error {
	l := ctxzap.Extract(ctx)

	if err := c.guardDeprovisionTarget(ctx, username); err != nil {
		return err
	}

	cm, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(ctx, argoCDConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf(
			"argocd-connector: failed to fetch ConfigMap '%s' in namespace '%s': %w",
			argoCDConfigMapName, argocdNamespace, err,
		)
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
		return fmt.Errorf(
			"argocd-connector: failed to delete account %q from ConfigMap '%s': %w",
			username, argoCDConfigMapName, err,
		)
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

	if err := c.guardDeprovisionTarget(ctx, username); err != nil {
		return err
	}

	secret, err := c.k8sClient.CoreV1().Secrets(argocdNamespace).Get(ctx, argoCDSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf(
			"argocd-connector: failed to fetch Secret '%s' in namespace '%s': %w",
			argoCDSecretName, argocdNamespace, err,
		)
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
		return fmt.Errorf(
			"argocd-connector: failed to purge stored credentials for account %q from Secret '%s': %w",
			username, argoCDSecretName, err,
		)
	}

	l.Debug("Purged stored credentials for Argo CD local account",
		zap.String("account", username),
		zap.Int("removed_keys", len(ops)),
	)
	return nil
}
