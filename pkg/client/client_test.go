package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := context.Background()
		client := NewClient(ctx, "https://test.com", "admin", "password", nil)

		assert.NotNil(t, client)
		assert.Equal(t, "https://test.com", client.apiUrl)
		assert.Equal(t, "admin", client.username)
		assert.Equal(t, "password", client.password)
	})
}

// Note: Tests for GetAccounts, GetRoles, etc. are skipped as they require
// the ArgoCD CLI to be installed and accessible.
// These integration tests should be run in an environment where ArgoCD CLI is available.

/*
func TestGetAccounts_Integration(t *testing.T) {
	// This test requires ArgoCD CLI to be installed and configured
	t.Skip("Integration test - requires ArgoCD CLI")

	ctx := context.Background()
	client := NewClient(ctx, "127.0.0.1:8080", "admin", "password", nil)

	accounts, err := client.GetAccounts(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, accounts)
}
*/
