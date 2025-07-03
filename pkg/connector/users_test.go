package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-argo-cd/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUserBuilder_List tests the List method of the UserBuilder.
func TestUserBuilder_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockAccounts := []*client.Account{
			{Name: "user1", Enabled: true},
			{Name: "user2", Enabled: false},
		}
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return mockAccounts, nil
			},
		}

		builder := newUserBuilder(mockCli)
		resources, nextPage, annos, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.NoError(t, err)
		assert.Empty(t, nextPage)
		assert.Nil(t, annos)
		assert.Len(t, resources, 2)
		assert.Equal(t, "user1", resources[0].DisplayName)
	})

	t.Run("client error", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return nil, errors.New("accounts error")
			},
		}

		builder := newUserBuilder(mockCli)
		_, _, _, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch user data")
	})
}

// TestUserBuilder_Entitlements tests the Entitlements method.
func TestUserBuilder_Entitlements(t *testing.T) {
	builder := newUserBuilder(nil)
	resource := &v2.Resource{
		Id: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "test-user"},
	}

	ents, nextPage, annos, err := builder.Entitlements(context.Background(), resource, &pagination.Token{})
	require.NoError(t, err)
	assert.Empty(t, nextPage)
	assert.Nil(t, annos)
	assert.Empty(t, ents)
}

// TestUserBuilder_Grants tests the Grants method.
func TestUserBuilder_Grants(t *testing.T) {
	builder := newUserBuilder(nil)
	resource := &v2.Resource{
		Id: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "test-user"},
	}

	grants, nextPage, annos, err := builder.Grants(context.Background(), resource, &pagination.Token{})
	require.NoError(t, err)
	assert.Empty(t, nextPage)
	assert.Nil(t, annos)
	assert.Empty(t, grants)
}
