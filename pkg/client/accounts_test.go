package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// newTestClient builds a Client that talks to the given Kubernetes fake and HTTP base URL,
// bypassing session authentication (which the authRoundTripper would otherwise perform).
func newTestClient(k8sClient kubernetes.Interface, apiURL string, httpClient *http.Client) *Client {
	return &Client{
		apiUrl:     apiURL,
		username:   "admin",
		password:   "password",
		k8sClient:  k8sClient,
		httpClient: httpClient,
	}
}

// newArgoCDConfigMap builds an argocd-cm ConfigMap fake with the given data.
func newArgoCDConfigMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      argoCDConfigMapName,
			Namespace: argocdNamespace,
		},
		Data: data,
	}
}

// newArgoCDSecret builds an argocd-secret Secret fake with the given data.
func newArgoCDSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      argoCDSecretName,
			Namespace: argocdNamespace,
		},
		Data: data,
	}
}

func getConfigMapData(t *testing.T, k8sClient kubernetes.Interface) map[string]string {
	t.Helper()
	cm, err := k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(context.Background(), argoCDConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)
	return cm.Data
}

func getSecretData(t *testing.T, k8sClient kubernetes.Interface) map[string][]byte {
	t.Helper()
	secret, err := k8sClient.CoreV1().Secrets(argocdNamespace).Get(context.Background(), argoCDSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	return secret.Data
}

// TestParseDeprovisionMode covers normalization of the configured deprovision mode.
func TestParseDeprovisionMode(t *testing.T) {
	t.Run("empty defaults to disable", func(t *testing.T) {
		mode, err := ParseDeprovisionMode("")
		require.NoError(t, err)
		assert.Equal(t, DeprovisionModeDisable, mode)
	})

	t.Run("normalizes case and whitespace", func(t *testing.T) {
		mode, err := ParseDeprovisionMode("  DELETE ")
		require.NoError(t, err)
		assert.Equal(t, DeprovisionModeDelete, mode)
	})

	t.Run("disable", func(t *testing.T) {
		mode, err := ParseDeprovisionMode("disable")
		require.NoError(t, err)
		assert.Equal(t, DeprovisionModeDisable, mode)
	})

	t.Run("rejects unknown mode", func(t *testing.T) {
		_, err := ParseDeprovisionMode("purge")
		require.Error(t, err)
		assert.Contains(t, err.Error(), `unsupported deprovision mode "purge"`)
	})
}

// TestJSONPointerEscape verifies JSON Pointer escaping of reserved characters.
func TestJSONPointerEscape(t *testing.T) {
	assert.Equal(t, "accounts.alice", jsonPointerEscape("accounts.alice"))
	assert.Equal(t, "a~1b", jsonPointerEscape("a/b"))
	assert.Equal(t, "a~0b", jsonPointerEscape("a~b"))
	assert.Equal(t, "/data/accounts.alice.enabled", dataKeyPath("accounts.alice.enabled"))
}

// TestDisableAccount_AddsEnabledKey verifies that disabling an account whose `enabled` key is
// absent adds it as "false" (Argo CD treats a missing key as enabled).
func TestDisableAccount_AddsEnabledKey(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.alice": "apiKey, login",
		"accounts.bob":   "login",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DisableAccount(ctx, "alice"))

	data := getConfigMapData(t, k8sClient)
	assert.Equal(t, "false", data["accounts.alice.enabled"])
	// The account entry itself is preserved so the change stays reversible.
	assert.Equal(t, "apiKey, login", data["accounts.alice"])
	// Other accounts are untouched.
	assert.Equal(t, "login", data["accounts.bob"])
	assert.NotContains(t, data, "accounts.bob.enabled")
}

// TestDisableAccount_ReplacesEnabledKey verifies that an explicit `enabled: true` is replaced.
func TestDisableAccount_ReplacesEnabledKey(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.alice":         "apiKey, login",
		"accounts.alice.enabled": "true",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DisableAccount(ctx, "alice"))

	assert.Equal(t, "false", getConfigMapData(t, k8sClient)["accounts.alice.enabled"])
}

// TestDisableAccount_AlreadyDisabled verifies that re-disabling an account succeeds without a
// second write, so a retried deprovision converges.
func TestDisableAccount_AlreadyDisabled(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.alice":         "apiKey, login",
		"accounts.alice.enabled": "false",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DisableAccount(ctx, "alice"))

	assert.Equal(t, "false", getConfigMapData(t, k8sClient)["accounts.alice.enabled"])

	var patched bool
	for _, action := range k8sClient.Actions() {
		if action.GetVerb() == "patch" {
			patched = true
		}
	}
	assert.False(t, patched, "already-disabled account should not be patched again")
}

// TestDisableAccount_AccountNotDefined verifies that an account missing from argocd-cm is treated
// as already deprovisioned rather than an error.
func TestDisableAccount_AccountNotDefined(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.bob": "login",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DisableAccount(ctx, "alice"))

	assert.NotContains(t, getConfigMapData(t, k8sClient), "accounts.alice.enabled")
}

// TestDisableAccount_NilConfigMapData verifies the empty-ConfigMap case does not attempt a patch
// against a non-existent /data object.
func TestDisableAccount_NilConfigMapData(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(nil))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DisableAccount(ctx, "alice"))
}

// TestDeprovision_AdminGuard verifies the built-in admin account is not deprovisionable through
// any of the deprovisioning operations.
func TestDeprovision_AdminGuard(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(
		newArgoCDConfigMap(map[string]string{"accounts.admin": "apiKey, login"}),
		newArgoCDSecret(map[string][]byte{"accounts.admin.password": []byte("hash")}),
	)
	cli := newTestClient(k8sClient, "https://test.com", nil)

	operations := map[string]func(context.Context, string) error{
		"DisableAccount":          cli.DisableAccount,
		"DeleteAccount":           cli.DeleteAccount,
		"PurgeAccountCredentials": cli.PurgeAccountCredentials,
		"RevokeAccountTokens":     cli.RevokeAccountTokens,
	}

	for name, operation := range operations {
		for _, target := range []string{"admin", "ADMIN"} {
			t.Run(fmt.Sprintf("%s/%s", name, target), func(t *testing.T) {
				err := operation(ctx, target)
				require.Error(t, err)
				assert.Contains(t, err.Error(), `refusing to deprovision the built-in "admin" account`)
			})
		}
	}

	// Nothing was written for the guarded account.
	assert.Equal(t, "apiKey, login", getConfigMapData(t, k8sClient)["accounts.admin"])
	assert.Contains(t, getSecretData(t, k8sClient), "accounts.admin.password")
}

// TestDeprovision_RejectsInvalidAccountName verifies account names that cannot name a real Argo CD
// local account are rejected before any patch is built.
func TestDeprovision_RejectsInvalidAccountName(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{"accounts.alice": "login"}))
	cli := newTestClient(k8sClient, "https://test.com", nil)

	for _, username := range []string{"", "alice/../bob", `alice", "x": "y`, "alice bob"} {
		t.Run(fmt.Sprintf("%q", username), func(t *testing.T) {
			require.Error(t, cli.DisableAccount(ctx, username))
			require.Error(t, cli.DeleteAccount(ctx, username))
			require.Error(t, cli.PurgeAccountCredentials(ctx, username))
			require.Error(t, cli.RevokeAccountTokens(ctx, username))
		})
	}

	assert.Equal(t, "login", getConfigMapData(t, k8sClient)["accounts.alice"])
}

// TestDeleteAccount_RemovesAccountKeys verifies both the capabilities entry and the enabled flag
// are removed, and that unrelated accounts survive.
func TestDeleteAccount_RemovesAccountKeys(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.alice":         "apiKey, login",
		"accounts.alice.enabled": "true",
		"accounts.bob":           "login",
		"admin.enabled":          "true",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DeleteAccount(ctx, "alice"))

	data := getConfigMapData(t, k8sClient)
	assert.NotContains(t, data, "accounts.alice")
	assert.NotContains(t, data, "accounts.alice.enabled")
	assert.Equal(t, "login", data["accounts.bob"])
	// The built-in admin switch is never touched.
	assert.Equal(t, "true", data["admin.enabled"])
}

// TestDeleteAccount_WithoutEnabledKey verifies deleting an account that has no enabled flag.
func TestDeleteAccount_WithoutEnabledKey(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.alice": "apiKey, login",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DeleteAccount(ctx, "alice"))

	assert.NotContains(t, getConfigMapData(t, k8sClient), "accounts.alice")
}

// TestDeleteAccount_AlreadyDeleted verifies a missing account key is success, not an error.
func TestDeleteAccount_AlreadyDeleted(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"accounts.bob": "login",
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.DeleteAccount(ctx, "alice"))
	// Idempotent: a second call is still a no-op success.
	require.NoError(t, cli.DeleteAccount(ctx, "alice"))
}

// TestPurgeAccountCredentials_RemovesStoredCredentials verifies the password hash, mtime marker
// and token records are removed from argocd-secret.
func TestPurgeAccountCredentials_RemovesStoredCredentials(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDSecret(map[string][]byte{
		"accounts.alice.password":      []byte("$2a$10$hash"),
		"accounts.alice.passwordMtime": []byte("2026-09-16T00:00:00Z"),
		"accounts.alice.tokens":        []byte(`[{"id":"token-1","iat":1}]`),
		"accounts.bob.password":        []byte("$2a$10$other"),
		"server.secretkey":             []byte("signing-key"),
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.PurgeAccountCredentials(ctx, "alice"))

	data := getSecretData(t, k8sClient)
	assert.NotContains(t, data, "accounts.alice.password")
	assert.NotContains(t, data, "accounts.alice.passwordMtime")
	assert.NotContains(t, data, "accounts.alice.tokens")
	// Other accounts and Argo CD's own secrets are untouched.
	assert.Equal(t, []byte("$2a$10$other"), data["accounts.bob.password"])
	assert.Equal(t, []byte("signing-key"), data["server.secretkey"])
}

// TestPurgeAccountCredentials_PartialKeys verifies only the keys that exist are removed; a
// `remove` op against a missing key would be rejected by the Kubernetes API.
func TestPurgeAccountCredentials_PartialKeys(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDSecret(map[string][]byte{
		"accounts.alice.tokens": []byte(`[{"id":"token-1","iat":1}]`),
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.PurgeAccountCredentials(ctx, "alice"))

	assert.NotContains(t, getSecretData(t, k8sClient), "accounts.alice.tokens")
}

// TestPurgeAccountCredentials_NothingStored verifies an account with no stored credentials is
// treated as already purged.
func TestPurgeAccountCredentials_NothingStored(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDSecret(map[string][]byte{
		"server.secretkey": []byte("signing-key"),
	}))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.PurgeAccountCredentials(ctx, "alice"))
	assert.Equal(t, []byte("signing-key"), getSecretData(t, k8sClient)["server.secretkey"])
}

// TestPurgeAccountCredentials_SecretMissing verifies a missing argocd-secret surfaces as an error
// rather than being reported as a successful purge.
func TestPurgeAccountCredentials_SecretMissing(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset()

	cli := newTestClient(k8sClient, "https://test.com", nil)
	err := cli.PurgeAccountCredentials(ctx, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch Secret 'argocd-secret'")
}

// TestGetAccount_NotFound verifies a 404 is reported as ErrAccountNotFound.
func TestGetAccount_NotFound(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

	_, err := cli.GetAccount(ctx, "alice")
	require.ErrorIs(t, err, ErrAccountNotFound)
}

// TestGetAccount_Success verifies account metadata (including token ids) is parsed.
func TestGetAccount_Success(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/account/alice", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"alice","enabled":false,"capabilities":["apiKey"],"tokens":[{"id":"t1","issuedAt":1}]}`))
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

	account, err := cli.GetAccount(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", account.Name)
	assert.False(t, account.Enabled)
	require.Len(t, account.Tokens, 1)
	assert.Equal(t, "t1", account.Tokens[0].ID)
}

// TestRevokeAccountTokens_RevokesEveryToken verifies every issued token is deleted through the
// Argo CD API.
func TestRevokeAccountTokens_RevokesEveryToken(t *testing.T) {
	ctx := context.Background()

	var mu sync.Mutex
	var revoked []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/account/alice":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"alice","tokens":[{"id":"t1"},{"id":"t2"}]}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/account/alice/token/"):
			mu.Lock()
			revoked = append(revoked, strings.TrimPrefix(r.URL.Path, "/api/v1/account/alice/token/"))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

	require.NoError(t, cli.RevokeAccountTokens(ctx, "alice"))
	assert.ElementsMatch(t, []string{"t1", "t2"}, revoked)
}

// TestRevokeAccountTokens_AccountAlreadyGone verifies an account Argo CD no longer knows about is
// treated as already deprovisioned.
func TestRevokeAccountTokens_AccountAlreadyGone(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())
	require.NoError(t, cli.RevokeAccountTokens(ctx, "alice"))
}

// TestRevokeAccountTokens_TokenAlreadyRevoked verifies a token that is already gone does not fail
// the deprovision.
func TestRevokeAccountTokens_TokenAlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"alice","tokens":[{"id":"t1"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())
	require.NoError(t, cli.RevokeAccountTokens(ctx, "alice"))
}

// TestRevokeAccountTokens_NoTokens verifies an account without tokens needs no API calls beyond
// the lookup.
func TestRevokeAccountTokens_NoTokens(t *testing.T) {
	ctx := context.Background()
	var deletes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"alice","enabled":true,"tokens":[]}`))
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())
	require.NoError(t, cli.RevokeAccountTokens(ctx, "alice"))
	assert.Zero(t, deletes)
}

// TestRevokeAccountTokens_ReportsFailures verifies a failed revocation is surfaced and does not
// stop the remaining tokens from being attempted.
func TestRevokeAccountTokens_ReportsFailures(t *testing.T) {
	ctx := context.Background()

	var attempted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"alice","tokens":[{"id":"t1"},{"id":"t2"}]}`))
			return
		}
		tokenID := strings.TrimPrefix(r.URL.Path, "/api/v1/account/alice/token/")
		attempted = append(attempted, tokenID)
		if tokenID == "t1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"permission denied"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

	err := cli.RevokeAccountTokens(ctx, "alice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `failed to revoke token "t1"`)
	assert.ElementsMatch(t, []string{"t1", "t2"}, attempted)
}

// TestMarshalJSONPatch verifies a remove operation omits the value field, which the Kubernetes API
// rejects when present on a remove.
func TestMarshalJSONPatch(t *testing.T) {
	patch, err := marshalJSONPatch([]jsonPatchOperation{
		{Op: jsonPatchOpRemove, Path: dataKeyPath("accounts.alice")},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `[{"op":"remove","path":"/data/accounts.alice"}]`, string(patch))

	value := accountDisabledValue
	patch, err = marshalJSONPatch([]jsonPatchOperation{
		{Op: jsonPatchOpAdd, Path: dataKeyPath("accounts.alice.enabled"), Value: &value},
	})
	require.NoError(t, err)

	var ops []map[string]any
	require.NoError(t, json.Unmarshal(patch, &ops))
	require.Len(t, ops, 1)
	assert.Equal(t, "false", ops[0]["value"])
}

// TestCreateAccount_ClearsStaleEnabledFlag verifies that re-provisioning an account that was
// previously deprovisioned in `disable` mode clears the leftover `accounts.<name>.enabled: false`
// key. Argo CD treats an account as enabled only when the key is absent, so leaving it behind
// would produce an account that cannot authenticate even though provisioning reported success.
func TestCreateAccount_ClearsStaleEnabledFlag(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(
		newArgoCDConfigMap(map[string]string{
			"accounts.leaver":         "apiKey, login",
			"accounts.leaver.enabled": "false",
			"accounts.bob.enabled":    "false",
		}),
		newArgoCDSecret(map[string][]byte{}),
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}))
	defer srv.Close()

	cli := newTestClient(k8sClient, srv.URL, srv.Client())
	_, _, err := cli.CreateAccount(ctx, "leaver", "new-password")
	require.NoError(t, err)

	data := getConfigMapData(t, k8sClient)
	assert.NotContains(t, data, "accounts.leaver.enabled", "stale disabled flag must be cleared")
	assert.Equal(t, "apiKey, login", data["accounts.leaver"])
	// A different account's flag is left alone.
	assert.Equal(t, "false", data["accounts.bob.enabled"])
}

// TestCreateAccount_RejectsInvalidAccountName verifies the create path validates account names
// with the same rules as the deprovision path, so a name cannot break out of the JSON Patch
// document or collide with another account's suffix namespace.
func TestCreateAccount_RejectsInvalidAccountName(t *testing.T) {
	ctx := context.Background()
	for _, username := range []string{"", "alice.enabled", `alice", "x": "y`, "alice bob", "alice/../bob"} {
		t.Run(username, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
				"accounts.alice.enabled": "false",
			}))
			cli := newTestClient(k8sClient, "https://test.com", nil)

			_, _, err := cli.CreateAccount(ctx, username, "pw")
			require.Error(t, err)
			// The store is unchanged.
			assert.Equal(t, "false", getConfigMapData(t, k8sClient)["accounts.alice.enabled"])
		})
	}
}

// TestDeprovision_RejectsDottedAccountName verifies that a dotted name is refused on every
// deprovision path. Argo CD splits `accounts.*` keys on "." and only accepts two- and three-part
// keys, so no real account name contains a dot -- and accepting one would let `alice.enabled`
// address the *enabled flag* of the separate account `alice`.
func TestDeprovision_RejectsDottedAccountName(t *testing.T) {
	ctx := context.Background()

	for _, username := range []string{"alice.enabled", "john.smith", "admin.enabled", ".", "alice."} {
		t.Run(username, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset(
				newArgoCDConfigMap(map[string]string{
					"accounts.alice":         "apiKey, login",
					"accounts.alice.enabled": "false",
				}),
				newArgoCDSecret(map[string][]byte{
					"accounts.alice.password": []byte("$2a$10$hash"),
				}),
			)
			cli := newTestClient(k8sClient, "https://test.com", nil)

			require.Error(t, cli.DisableAccount(ctx, username))
			require.Error(t, cli.DeleteAccount(ctx, username))
			require.Error(t, cli.PurgeAccountCredentials(ctx, username))
			require.Error(t, cli.RevokeAccountTokens(ctx, username))

			// Nothing was written: the disabled account keeps its flag and its credentials.
			data := getConfigMapData(t, k8sClient)
			assert.Equal(t, "apiKey, login", data["accounts.alice"])
			assert.Equal(t, "false", data["accounts.alice.enabled"])
		})
	}
}

// TestCreateAccount_NilConfigMapData verifies an account can be created when argocd-cm has no
// `data` map at all -- the state of Argo CD's upstream install manifests, and therefore of any
// cluster with no local accounts yet. A JSON Patch `add` needs its parent container to exist, so
// the missing `data` object has to be created in the same patch.
func TestCreateAccount_NilConfigMapData(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(nil))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}))
	defer srv.Close()

	cli := newTestClient(k8sClient, srv.URL, srv.Client())
	account, _, err := cli.CreateAccount(ctx, "first-account", "pw")
	require.NoError(t, err)
	require.NotNil(t, account)

	assert.Equal(t, "apiKey, login", getConfigMapData(t, k8sClient)["accounts.first-account"])
}

// TestCreateAccount_PreservesUnrelatedConfigMapKeys verifies creating an account never clobbers
// the rest of argocd-cm. A JSON Patch that created the `data` container unconditionally would
// replace the whole map; the merge patch used here adds one key and leaves everything else in
// place, including other local accounts and Argo CD's own settings.
func TestCreateAccount_PreservesUnrelatedConfigMapKeys(t *testing.T) {
	ctx := context.Background()
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{
		"url":                  "https://argocd.example.com",
		"oidc.config":          "name: Okta",
		"policy.default":       "role:readonly",
		"accounts.bob":         "login",
		"accounts.bob.enabled": "false",
	}))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"t"}`))
	}))
	defer srv.Close()

	cli := newTestClient(k8sClient, srv.URL, srv.Client())
	_, _, err := cli.CreateAccount(ctx, "alice", "pw")
	require.NoError(t, err)

	data := getConfigMapData(t, k8sClient)
	assert.Equal(t, "apiKey, login", data["accounts.alice"])
	// Argo CD's own settings survive.
	assert.Equal(t, "https://argocd.example.com", data["url"])
	assert.Equal(t, "name: Okta", data["oidc.config"])
	assert.Equal(t, "role:readonly", data["policy.default"])
	// Another account, including its disabled flag, is untouched.
	assert.Equal(t, "login", data["accounts.bob"])
	assert.Equal(t, "false", data["accounts.bob.enabled"])
}
