package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		client, err := NewClient(ctx, "https://test.com", "admin", "password", getMinimalKubeconfig())
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
	client, err := NewClient(ctx, "127.0.0.1:8080", "admin", "password", getMinimalKubeconfig())
	require.NoError(t, err)

	accounts, err := client.GetAccounts(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, accounts)
}

func TestUpdateUserRole_AlreadyExists(t *testing.T) {
	t.Skip("This test requires a running Kubernetes cluster with Argo CD installed.")
	ctx := context.Background()
	client, err := NewClient(ctx, "127.0.0.1:8080", "admin", "password", getMinimalKubeconfig())
	require.NoError(t, err)

	userID := "test-user"
	roleID := "test-role"

	_, err = client.UpdateUserRole(ctx, userID, roleID)
	require.NoError(t, err)

	_, err = client.UpdateUserRole(ctx, userID, roleID)
	assert.NoError(t, err)
}
