package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		client := NewClient(ctx, "https://test.com", "admin", "password")

		assert.NotNil(t, client)
		assert.Equal(t, "https://test.com", client.apiUrl)
		assert.Equal(t, "admin", client.username)
		assert.Equal(t, "password", client.password)
	})
}

// TestGetAccounts_Integration is an integration test that requires ArgoCD CLI to be installed and configured.
func TestGetAccounts_Integration(t *testing.T) {
	t.Skip("Integration test - requires ArgoCD CLI")
	ctx := context.Background()
	client := NewClient(ctx, "127.0.0.1:8080", "admin", "password")

	accounts, err := client.GetAccounts(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, accounts)
}
