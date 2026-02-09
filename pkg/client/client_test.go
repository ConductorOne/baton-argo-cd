package client

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// getMinimalKubeconfig returns a minimal valid kubeconfig for testing purposes.
// This kubeconfig won't actually connect to a real cluster but will pass validation.
func getMinimalKubeconfig() []byte {
	return []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://example.com
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user: {}
`)
}

// TestNewClient tests the NewClient function.
func TestNewClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		client, err := NewClient(ctx, "https://test.com", "admin", "password", getMinimalKubeconfig(), false, nil)
		require.NoError(t, err)

		assert.NotNil(t, client)
		assert.Equal(t, "https://test.com", client.apiUrl)
		assert.Equal(t, "admin", client.username)
		assert.Equal(t, "password", client.password)
	})
}

// TestGetAccounts_Integration tests the GetAccounts function.
func TestGetAccounts_Integration(t *testing.T) {
	t.Skip("Integration test - requires ArgoCD CLI")
	ctx := context.Background()
	client, err := NewClient(ctx, "127.0.0.1:8080", "admin", "password", getMinimalKubeconfig(), false, nil)
	require.NoError(t, err)

	accounts, err := client.GetAccounts(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, accounts)
}

func TestUpdateUserRole_AlreadyExists(t *testing.T) {
	t.Skip("This test requires a running Kubernetes cluster with Argo CD installed.")
	ctx := context.Background()
	client, err := NewClient(ctx, "127.0.0.1:8080", "admin", "password", getMinimalKubeconfig(), false, nil)
	require.NoError(t, err)

	userID := "test-user"
	roleID := "test-role"

	_, err = client.UpdateUserRole(ctx, userID, roleID)
	require.NoError(t, err)

	_, err = client.UpdateUserRole(ctx, userID, roleID)
	assert.NoError(t, err)
}

// TestUpdateUserRole_BuiltInRoleAdmin tests that admin role bypasses validation.
func TestUpdateUserRole_BuiltInRoleAdmin(t *testing.T) {
	ctx := context.Background()

	fakeK8sClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv": "",
		},
	})

	client := &Client{
		apiUrl:         "https://test.com",
		username:       "admin",
		password:       "password",
		kubeconfigFile: getMinimalKubeconfig(),
		k8sClient:      fakeK8sClient,
	}

	annos, err := client.UpdateUserRole(ctx, "test-user", "admin")
	require.NoError(t, err)
	assert.Nil(t, annos)

	cm, err := fakeK8sClient.CoreV1().ConfigMaps("argocd").Get(ctx, "argocd-rbac-cm", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, cm.Data["policy.csv"], "g,test-user,role:admin")
}

// TestUpdateUserRole_BuiltInRoleReadonly tests that readonly role bypasses validation.
func TestUpdateUserRole_BuiltInRoleReadonly(t *testing.T) {
	ctx := context.Background()

	fakeK8sClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv": "",
		},
	})

	client := &Client{
		apiUrl:         "https://test.com",
		username:       "admin",
		password:       "password",
		kubeconfigFile: getMinimalKubeconfig(),
		k8sClient:      fakeK8sClient,
	}

	annos, err := client.UpdateUserRole(ctx, "test-user", "readonly")
	require.NoError(t, err)
	assert.Nil(t, annos)

	cm, err := fakeK8sClient.CoreV1().ConfigMaps("argocd").Get(ctx, "argocd-rbac-cm", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, cm.Data["policy.csv"], "g,test-user,role:readonly")
}

// TestUpdateUserRole_CustomRoleExists tests granting a custom role that exists in ConfigMap.
func TestUpdateUserRole_CustomRoleExists(t *testing.T) {
	ctx := context.Background()

	fakeK8sClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv": "p, role:deployer, applications, get, */*, allow\n",
		},
	})

	client := &Client{
		apiUrl:         "https://test.com",
		username:       "admin",
		password:       "password",
		kubeconfigFile: getMinimalKubeconfig(),
		k8sClient:      fakeK8sClient,
	}

	annos, err := client.UpdateUserRole(ctx, "test-user", "deployer")
	require.NoError(t, err)
	assert.Nil(t, annos)

	cm, err := fakeK8sClient.CoreV1().ConfigMaps("argocd").Get(ctx, "argocd-rbac-cm", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Contains(t, cm.Data["policy.csv"], "g,test-user,role:deployer")
}

// TestUpdateUserRole_CustomRoleNotFound tests that non-existent custom roles are rejected.
func TestUpdateUserRole_CustomRoleNotFound(t *testing.T) {
	ctx := context.Background()

	fakeK8sClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv": "p, role:deployer, applications, get, */*, allow\n",
		},
	})

	client := &Client{
		apiUrl:         "https://test.com",
		username:       "admin",
		password:       "password",
		kubeconfigFile: getMinimalKubeconfig(),
		k8sClient:      fakeK8sClient,
	}

	annos, err := client.UpdateUserRole(ctx, "test-user", "non-existent")
	require.Error(t, err)
	assert.Nil(t, annos)
	assert.Contains(t, err.Error(), "argocd-connector: role definition not found in argocd-rbac-cm ConfigMap")
}

// TestUpdateUserRole_RoleValidationErrorMessage verifies the error message format.
func TestUpdateUserRole_RoleValidationErrorMessage(t *testing.T) {
	ctx := context.Background()

	fakeK8sClient := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-rbac-cm",
			Namespace: "argocd",
		},
		Data: map[string]string{
			"policy.csv": "",
		},
	})

	client := &Client{
		apiUrl:         "https://test.com",
		username:       "admin",
		password:       "password",
		kubeconfigFile: getMinimalKubeconfig(),
		k8sClient:      fakeK8sClient,
	}

	annos, err := client.UpdateUserRole(ctx, "test-user", "custom-role")
	require.Error(t, err)
	assert.Nil(t, annos)

	errorMsg := err.Error()
	assert.True(t, strings.Contains(errorMsg, "argocd-connector: role definition not found in argocd-rbac-cm ConfigMap"))
	assert.True(t, strings.Contains(errorMsg, "Role 'custom-role' must be defined with a policy line"))
	assert.True(t, strings.Contains(errorMsg, "p, role:custom-role, resource, action, object, effect"))
	assert.True(t, strings.Contains(errorMsg, "Add the role definition to the argocd-rbac-cm ConfigMap in the 'policy.csv' key"))
}
