package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/stretchr/testify/assert"
)

// loadAccountsResponseFromMock loads a AccountsResponse from a mock JSON file for testing.
func loadAccountsResponseFromMock(t *testing.T, file string) AccountsResponse {
	var accounts AccountsResponse
	mockData, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("failed to read mock data: %v", err)
	}
	if err := json.Unmarshal(mockData, &accounts); err != nil {
		t.Fatalf("failed to unmarshal mock data: %v", err)
	}
	return accounts
}

func TestGetAccounts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockResp := loadAccountsResponseFromMock(t, "../../test/mock/accounts_success.json")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Contains(t, r.URL.String(), accountsEndpoint)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(mockResp)
		}))
		defer server.Close()

		ctx := context.Background()
		httpClient, _ := uhttp.NewBaseHttpClientWithContext(ctx, &http.Client{})
		client := NewClient(ctx, server.URL, "dummy-token", httpClient)

		accounts, err := client.GetAccounts(ctx)
		assert.NoError(t, err)
		assert.Len(t, accounts, 2)
		assert.Equal(t, "admin", accounts[0].Name)
	})

	t.Run("error, invalid URL", func(t *testing.T) {
		ctx := context.Background()
		httpClient, _ := uhttp.NewBaseHttpClientWithContext(ctx, &http.Client{})
		client := NewClient(ctx, "::bad_url::", "token", httpClient)
		_, err := client.GetAccounts(ctx)
		assert.Error(t, err)
	})

	t.Run("error, server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()
		ctx := context.Background()
		httpClient, _ := uhttp.NewBaseHttpClientWithContext(ctx, &http.Client{})
		client := NewClient(ctx, server.URL, "dummy-token", httpClient)
		_, err := client.GetAccounts(ctx)
		assert.Error(t, err)
	})
}
