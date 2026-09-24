package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newRBACConfigMap(policy *string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbacConfigMapName,
			Namespace: argocdNamespace,
		},
	}
	if policy != nil {
		cm.Data = map[string]string{policyCSVKey: *policy}
	}
	return cm
}

func getRBACPolicy(t *testing.T, k8sClient *fake.Clientset) string {
	t.Helper()
	cm, err := k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(context.Background(), rbacConfigMapName, metav1.GetOptions{})
	require.NoError(t, err)
	return cm.Data[policyCSVKey]
}

// statusServer answers every Argo CD API request with the given HTTP status.
func statusServer(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":"upstream"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestGetAccount_ErrorCodes verifies Argo CD API failures reach callers with the gRPC code for
// their HTTP status, so C1 can tell a permission problem from a transient one.
func TestGetAccount_ErrorCodes(t *testing.T) {
	for httpStatus, want := range map[int]codes.Code{
		http.StatusUnauthorized:        codes.Unauthenticated,
		http.StatusForbidden:           codes.PermissionDenied,
		http.StatusNotFound:            codes.NotFound,
		http.StatusTooManyRequests:     codes.Unavailable,
		http.StatusInternalServerError: codes.Unavailable,
	} {
		t.Run(http.StatusText(httpStatus), func(t *testing.T) {
			srv := statusServer(t, httpStatus)
			cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

			_, err := cli.GetAccount(context.Background(), "alice")
			assert.Equal(t, want, status.Code(err))
			if httpStatus == http.StatusNotFound {
				require.ErrorIs(t, err, ErrAccountNotFound)
			}
		})
	}
}

// TestRevokeAccountTokens_TokenRevocationErrorCode verifies a failed token revocation keeps the
// code of its HTTP status.
func TestRevokeAccountTokens_TokenRevocationErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"name":"alice","enabled":true,"tokens":[{"id":"t1"}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())
	err := cli.RevokeAccountTokens(context.Background(), "alice")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestRotateAccountPassword_ErrorCodes verifies a rejected password update keeps the code of its
// HTTP status, e.g. a password that fails Argo CD's complexity rule is InvalidArgument.
func TestRotateAccountPassword_ErrorCodes(t *testing.T) {
	for httpStatus, want := range map[int]codes.Code{
		http.StatusBadRequest:          codes.InvalidArgument,
		http.StatusForbidden:           codes.PermissionDenied,
		http.StatusInternalServerError: codes.Unavailable,
	} {
		t.Run(http.StatusText(httpStatus), func(t *testing.T) {
			srv, _ := passwordAPIServer(t, map[string]bool{"alice": true}, httpStatus)
			cli := newTestClient(fake.NewSimpleClientset(), srv.URL, srv.Client())

			err := cli.RotateAccountPassword(context.Background(), "alice", "n3w-pass")
			assert.Equal(t, want, status.Code(err))
		})
	}
}

// failingClientset returns a fake clientset whose verb on resource fails with err.
func failingClientset(verb string, resource string, err error, objects ...runtime.Object) *fake.Clientset {
	k8sClient := fake.NewSimpleClientset(objects...)
	k8sClient.PrependReactor(verb, resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return k8sClient
}

// TestKubernetesErrors_Codes verifies Kubernetes API failures on every account operation keep
// the gRPC code for their status.
func TestKubernetesErrors_Codes(t *testing.T) {
	configMaps := schema.GroupResource{Resource: "configmaps"}
	secrets := schema.GroupResource{Resource: "secrets"}
	policy := "g, alice, role:dev\n"
	objects := []runtime.Object{
		newArgoCDConfigMap(map[string]string{"accounts.alice": "login", "accounts.alice.enabled": "false"}),
		newArgoCDSecret(map[string][]byte{"accounts.alice.password": []byte("hash")}),
		newRBACConfigMap(&policy),
	}

	tests := []struct {
		name      string
		verb      string
		resource  string
		err       error
		operation func(*Client) error
		want      codes.Code
	}{
		{
			name: "disable, configmap get forbidden", verb: "get", resource: "configmaps",
			err:       apierrors.NewForbidden(configMaps, argoCDConfigMapName, nil),
			operation: func(c *Client) error { return c.SetAccountEnabled(context.Background(), "alice", false) },
			want:      codes.PermissionDenied,
		},
		{
			name: "enable, configmap patch throttled", verb: "patch", resource: "configmaps",
			err:       apierrors.NewTooManyRequests("slow down", 1),
			operation: func(c *Client) error { return c.SetAccountEnabled(context.Background(), "alice", true) },
			want:      codes.Unavailable,
		},
		{
			name: "delete, configmap patch conflict", verb: "patch", resource: "configmaps",
			err:       apierrors.NewConflict(configMaps, argoCDConfigMapName, nil),
			operation: func(c *Client) error { return c.DeleteAccount(context.Background(), "alice") },
			want:      codes.AlreadyExists,
		},
		{
			name: "purge, secret get forbidden", verb: "get", resource: "secrets",
			err:       apierrors.NewForbidden(secrets, argoCDSecretName, nil),
			operation: func(c *Client) error { return c.PurgeAccountCredentials(context.Background(), "alice") },
			want:      codes.PermissionDenied,
		},
		{
			name: "purge, secret missing", verb: "get", resource: "secrets",
			err:       apierrors.NewNotFound(secrets, argoCDSecretName),
			operation: func(c *Client) error { return c.PurgeAccountCredentials(context.Background(), "alice") },
			want:      codes.NotFound,
		},
		{
			name: "rbac policies, rbac configmap get forbidden", verb: "get", resource: "configmaps",
			err:       apierrors.NewForbidden(configMaps, rbacConfigMapName, nil),
			operation: func(c *Client) error { return c.RemoveAccountPolicies(context.Background(), "alice") },
			want:      codes.PermissionDenied,
		},
		{
			name: "rbac policies, rbac configmap patch unavailable", verb: "patch", resource: "configmaps",
			err:       apierrors.NewServiceUnavailable("api server down"),
			operation: func(c *Client) error { return c.RemoveAccountPolicies(context.Background(), "alice") },
			want:      codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := newTestClient(failingClientset(tt.verb, tt.resource, tt.err, objects...), "https://test.com", nil)
			err := tt.operation(cli)
			require.Error(t, err)
			assert.Equal(t, tt.want, status.Code(err))
		})
	}
}

// TestManagedAccount_RefusesSelfLockout verifies every change that revokes access refuses the
// account the connector authenticates as, before anything is written, while enabling it is
// allowed.
func TestManagedAccount_RefusesSelfLockout(t *testing.T) {
	ctx := context.Background()
	policy := "g, svc-baton, role:admin\n"
	cmData := map[string]string{"accounts.svc-baton": "apiKey, login", "accounts.svc-baton.enabled": "false"}
	secretData := map[string][]byte{"accounts.svc-baton.password": []byte("hash")}
	k8sClient := fake.NewSimpleClientset(newArgoCDConfigMap(cmData), newArgoCDSecret(secretData), newRBACConfigMap(&policy))

	srv := statusServer(t, http.StatusOK)
	cli := newTestClient(k8sClient, srv.URL, srv.Client())
	cli.username = "svc-baton"

	operations := map[string]func(string) error{
		"SetAccountEnabled(false)": func(u string) error { return cli.SetAccountEnabled(ctx, u, false) },
		"DeleteAccount":            func(u string) error { return cli.DeleteAccount(ctx, u) },
		"PurgeAccountCredentials":  func(u string) error { return cli.PurgeAccountCredentials(ctx, u) },
		"RevokeAccountTokens":      func(u string) error { return cli.RevokeAccountTokens(ctx, u) },
		"RemoveAccountPolicies":    func(u string) error { return cli.RemoveAccountPolicies(ctx, u) },
		"RotateAccountPassword":    func(u string) error { return cli.RotateAccountPassword(ctx, u, "n3w-pass") },
	}

	for name, operation := range operations {
		for _, target := range []string{"svc-baton", "SVC-BATON"} {
			t.Run(name+"/"+target, func(t *testing.T) {
				err := operation(target)
				require.ErrorIs(t, err, ErrInvalidAccountTarget)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assert.Contains(t, err.Error(), "the connector authenticates as this account")
			})
		}
	}

	assert.Zero(t, patchCount(k8sClient), "a refused change must not write anything")
	assert.Equal(t, policy, getRBACPolicy(t, k8sClient))

	// Enabling the connector's own account restores access rather than removing it.
	require.NoError(t, cli.SetAccountEnabled(ctx, "svc-baton", true))
	assert.NotContains(t, getConfigMapData(t, k8sClient), "accounts.svc-baton.enabled")
}

// TestManagedAccount_AdminErrorCode verifies the admin guard is reported as InvalidArgument.
func TestManagedAccount_AdminErrorCode(t *testing.T) {
	cli := newTestClient(fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{"accounts.admin": "login"})), "https://test.com", nil)
	err := cli.SetAccountEnabled(context.Background(), "admin", false)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRemoveAccountPolicies verifies the account's own role grants and direct permissions are
// removed, while other subjects' lines -- including names that merely start with the account's --
// and role definitions are kept.
func TestRemoveAccountPolicies(t *testing.T) {
	policy := strings.Join([]string{
		"# team roles",
		"p, role:dev, applications, get, */*, allow",
		"g, alice, role:dev",
		"g, alice, role:ops",
		"g, bob, role:dev",
		"g, alice-admin, role:ops",
		"p, alice, applications, sync, default/*, allow",
		"p, alice-admin, applications, delete, default/*, allow",
		"",
	}, "\n")
	k8sClient := fake.NewSimpleClientset(newRBACConfigMap(&policy))

	cli := newTestClient(k8sClient, "https://test.com", nil)
	require.NoError(t, cli.RemoveAccountPolicies(context.Background(), "alice"))

	records, err := parsePolicyCSV(getRBACPolicy(t, k8sClient))
	require.NoError(t, err)
	assert.Equal(t, [][]string{
		{"p", "role:dev", "applications", "get", "*/*", "allow"},
		{"g", "bob", "role:dev"},
		{"g", "alice-admin", "role:ops"},
		{"p", "alice-admin", "applications", "delete", "default/*", "allow"},
	}, records)
}

// TestRemoveAccountPolicies_NothingToRemove verifies an account with no policy lines, or an RBAC
// ConfigMap with no policy at all, leaves the ConfigMap untouched.
func TestRemoveAccountPolicies_NothingToRemove(t *testing.T) {
	otherPolicy := "g, bob, role:dev\n"
	for name, policy := range map[string]*string{
		"no policy lines for account": &otherPolicy,
		"no policy":                   nil,
	} {
		t.Run(name, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset(newRBACConfigMap(policy))

			cli := newTestClient(k8sClient, "https://test.com", nil)
			require.NoError(t, cli.RemoveAccountPolicies(context.Background(), "alice"))
			assert.Zero(t, patchCount(k8sClient))
		})
	}
}

// TestCodedErrors_MessageNotRepeated verifies a coded error states its cause once, both on its own
// and after a caller wraps it, while keeping the gRPC code and the typed cause.
func TestCodedErrors_MessageNotRepeated(t *testing.T) {
	cli := newTestClient(fake.NewSimpleClientset(newArgoCDConfigMap(map[string]string{"accounts.bob": "login"})), "https://test.com", nil)

	err := cli.SetAccountEnabled(context.Background(), "ghost", false)
	require.ErrorIs(t, err, ErrAccountNotFound)
	assert.Equal(t, 1, strings.Count(err.Error(), "ghost is not defined"))

	wrapped := fmt.Errorf("baton-argo-cd: failed to disable account %q: %w", "ghost", err)
	st, ok := status.FromError(wrapped)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Equal(t, 1, strings.Count(st.Message(), "ghost is not defined"))
	require.ErrorIs(t, wrapped, ErrAccountNotFound)
}
