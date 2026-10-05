package client

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// captureWarnings returns a context whose logger records Warn and above, and a function returning
// each recorded entry's fields, decoded from JSON.
func captureWarnings(t *testing.T) (context.Context, func() []map[string]interface{}) {
	t.Helper()
	var buf bytes.Buffer
	encoderConfig := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderConfig), zapcore.AddSync(&buf), zapcore.WarnLevel)
	ctx := ctxzap.ToContext(context.Background(), zap.New(core))

	return ctx, func() []map[string]interface{} {
		var entries []map[string]interface{}
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var entry map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(line), &entry))
			entries = append(entries, entry)
		}
		return entries
	}
}

// TestRemoveAccountPolicies_SSOGroupWarning verifies removing an account's role grants warns that a
// same-named SSO group may have lost them too, but only when that overlap is possible: SSO is
// configured (or its configuration cannot be read) and at least one `g` line was removed. The
// removal itself always succeeds.
func TestRemoveAccountPolicies_SSOGroupWarning(t *testing.T) {
	grantAndPermission := "g, alice, role:dev\np, alice, applications, get, */*, allow\ng, bob, role:dev\n"
	permissionOnly := "p, alice, applications, get, */*, allow\ng, bob, role:dev\n"
	oidc := map[string]string{"accounts.alice": "login", "oidc.config": "name: Okta\nissuer: https://example.okta.com\n"}

	tests := []struct {
		name        string
		policy      string
		argoCDCM    map[string]string // nil means no argocd-cm
		getCMErr    error
		wantWarning bool
		wantErrLog  bool
	}{
		{name: "oidc configured", policy: grantAndPermission, argoCDCM: oidc, wantWarning: true},
		{
			name:   "dex configured",
			policy: grantAndPermission,
			argoCDCM: map[string]string{
				"url":        "https://argocd.example.com",
				"dex.config": "connectors:\n- type: github\n  id: github\n  name: GitHub\n",
			},
			wantWarning: true,
		},
		{
			// Argo CD ignores dex.config without url, so SSO is not configured.
			name:     "dex config without url",
			policy:   grantAndPermission,
			argoCDCM: map[string]string{"dex.config": "connectors:\n- type: github\n"},
		},
		{name: "no sso", policy: grantAndPermission, argoCDCM: map[string]string{"accounts.alice": "login"}},
		{name: "argocd-cm missing", policy: grantAndPermission},
		{
			// A group claim is only evaluated when it is the subject of a `g` line.
			name:     "only permissions removed",
			policy:   permissionOnly,
			argoCDCM: oidc,
		},
		{
			name:        "sso configuration unreadable",
			policy:      grantAndPermission,
			argoCDCM:    oidc,
			getCMErr:    apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, argoCDConfigMapName, nil),
			wantWarning: true,
			wantErrLog:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objects := []runtime.Object{newRBACConfigMap(&tt.policy)}
			if tt.argoCDCM != nil {
				objects = append(objects, newArgoCDConfigMap(tt.argoCDCM))
			}
			k8sClient := fake.NewSimpleClientset(objects...)
			if tt.getCMErr != nil {
				// Fail only reads of argocd-cm, so argocd-rbac-cm is still read and updated.
				k8sClient.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.(k8stesting.GetAction).GetName() == argoCDConfigMapName {
						return true, nil, tt.getCMErr
					}
					return false, nil, nil
				})
			}

			ctx, warnings := captureWarnings(t)

			cli := newTestClient(k8sClient, "https://test.com", nil)
			require.NoError(t, cli.RemoveAccountPolicies(ctx, "alice"))

			records, err := parsePolicyCSV(getRBACPolicy(t, k8sClient))
			require.NoError(t, err)
			assert.Equal(t, [][]string{{"g", "bob", "role:dev"}}, records, "the account's lines must be removed either way")

			entries := warnings()
			if !tt.wantWarning {
				assert.Empty(t, entries)
				return
			}

			require.Len(t, entries, 1)
			fields := entries[0]
			assert.Equal(t, "warn", fields["level"])
			assert.Equal(t, "alice", fields["account"])
			assert.Equal(t, []interface{}{"g, alice, role:dev"}, fields["removed_grants"],
				"only role grants can be shared with an SSO group")
			_, hasErr := fields["error"]
			assert.Equal(t, tt.wantErrLog, hasErr)
		})
	}
}
