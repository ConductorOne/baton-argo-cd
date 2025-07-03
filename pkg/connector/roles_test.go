package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-argo-cd/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleBuilder_List tests the List method of the RoleBuilder.
func TestRoleBuilder_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRoles := []*client.Role{
			{Name: "role1"},
			{Name: "role2"},
		}
		mockCli := &test.MockClient{
			GetRolesFunc: func(ctx context.Context) ([]*client.Role, annotations.Annotations, error) {
				return mockRoles, nil, nil
			},
		}

		builder := newRoleBuilder(mockCli)
		resources, nextPage, annos, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.NoError(t, err)
		assert.Empty(t, nextPage)
		assert.Nil(t, annos)
		assert.Len(t, resources, 2)
		assert.Equal(t, "role1", resources[0].DisplayName)
	})

	t.Run("client error", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetRolesFunc: func(ctx context.Context) ([]*client.Role, annotations.Annotations, error) {
				return nil, nil, errors.New("client error")
			},
		}

		builder := newRoleBuilder(mockCli)
		_, _, _, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.Error(t, err)
		assert.EqualError(t, err, "client error")
	})
}

// TestRoleBuilder_Entitlements tests the Entitlements method of the RoleBuilder.
func TestRoleBuilder_Entitlements(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		builder := newRoleBuilder(nil)
		resource := &v2.Resource{
			Id:          &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "test-role"},
			DisplayName: "Test Role",
		}
		ents, nextPage, annos, err := builder.Entitlements(context.Background(), resource, &pagination.Token{})
		require.NoError(t, err)
		assert.Empty(t, nextPage)
		assert.Nil(t, annos)
		assert.Len(t, ents, 1)
		assert.Equal(t, "assigned", ents[0].Slug)
	})
}

// TestRoleBuilder_Grants tests the Grants method of the RoleBuilder.
func TestRoleBuilder_Grants(t *testing.T) {
	t.Run("success for role with explicit grants", func(t *testing.T) {
		roleResource := &v2.Resource{
			Id: &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "role1"},
		}
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return []*client.Account{{Name: "user1"}}, nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{
					{Subject: "user1", Role: "role1"},
					{Subject: "user2", Role: "role2"},
				}, nil, nil
			},
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "", nil
			},
			GetSubjectsForRoleFunc: func(ctx context.Context, roleName string) ([]string, error) {
				if roleName == "role1" {
					return []string{"user1"}, nil
				}
				return nil, nil
			},
		}

		builder := newRoleBuilder(mockCli)
		grants, _, _, err := builder.Grants(context.Background(), roleResource, &pagination.Token{})
		require.NoError(t, err)
		assert.Len(t, grants, 1)
		assert.Equal(t, "user1", grants[0].Principal.Id.Resource)
	})

	t.Run("success for default role", func(t *testing.T) {
		roleResource := &v2.Resource{
			Id: &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "default-role"},
		}
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return []*client.Account{{Name: "user1"}}, nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return nil, nil, nil
			},
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
			GetSubjectsForRoleFunc: func(ctx context.Context, roleName string) ([]string, error) {
				return nil, nil
			},
		}

		builder := newRoleBuilder(mockCli)
		grants, _, _, err := builder.Grants(context.Background(), roleResource, &pagination.Token{})
		require.NoError(t, err)
		assert.Len(t, grants, 1)
		assert.Equal(t, "user1", grants[0].Principal.Id.Resource)
	})

	t.Run("error getting all user data", func(t *testing.T) {
		roleResource := &v2.Resource{
			Id: &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "some-role"},
		}
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return nil, errors.New("get accounts error")
			},
		}

		builder := newRoleBuilder(mockCli)
		_, _, _, err := builder.Grants(context.Background(), roleResource, &pagination.Token{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get users for role")
	})
}
