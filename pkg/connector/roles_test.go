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
	"google.golang.org/protobuf/reflect/protoreflect"
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

func hasAnnotation(annos annotations.Annotations, target protoreflect.ProtoMessage) bool {
	for _, a := range annos {
		if a.TypeUrl == "type.googleapis.com/"+string(target.ProtoReflect().Descriptor().FullName()) {
			return true
		}
	}
	return false
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

// TestRoleBuilder_Grant tests the Grant method of the RoleBuilder.
func TestRoleBuilder_Grant(t *testing.T) {
	principal := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     "test-user",
		},
	}
	entitlement := &v2.Entitlement{
		Resource: &v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: roleResourceType.Id,
				Resource:     "new-role",
			},
		},
	}

	t.Run("success", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "old-role"}}, nil, nil
			},
			UpdateUserRoleFunc: func(ctx context.Context, userID, roleID string) (annotations.Annotations, error) {
				assert.Equal(t, "test-user", userID)
				assert.Equal(t, "new-role", roleID)
				return nil, nil
			},
		}
		builder := newRoleBuilder(mockCli)
		grants, annos, err := builder.Grant(context.Background(), principal, entitlement)
		require.NoError(t, err)
		assert.Nil(t, annos)
		assert.Len(t, grants, 1)
		assert.Equal(t, "new-role", grants[0].Entitlement.Resource.Id.Resource)
		assert.Equal(t, "test-user", grants[0].Principal.Id.Resource)
	})

	t.Run("already exists", func(t *testing.T) {
		entitlement := &v2.Entitlement{
			Resource: &v2.Resource{
				Id: &v2.ResourceId{
					ResourceType: roleResourceType.Id,
					Resource:     "existing-role",
				},
			},
		}
		mockCli := &test.MockClient{
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "existing-role"}}, nil, nil
			},
		}
		builder := newRoleBuilder(mockCli)
		grants, annos, err := builder.Grant(context.Background(), principal, entitlement)
		require.NoError(t, err)
		assert.Nil(t, grants)
		assert.NotNil(t, annos)
		assert.True(t, hasAnnotation(annos, &v2.GrantAlreadyExists{}))
	})

	t.Run("get policy grants fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return nil, nil, errors.New("policy error")
			},
		}
		builder := newRoleBuilder(mockCli)
		_, _, err := builder.Grant(context.Background(), principal, entitlement)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get policy grants")
	})

	t.Run("update user role fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "old-role"}}, nil, nil
			},
			UpdateUserRoleFunc: func(ctx context.Context, userID, roleID string) (annotations.Annotations, error) {
				return nil, errors.New("update error")
			},
		}
		builder := newRoleBuilder(mockCli)
		_, _, err := builder.Grant(context.Background(), principal, entitlement)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update user role")
	})
}

// TestRoleBuilder_Revoke tests the Revoke method of the RoleBuilder.
func TestRoleBuilder_Revoke(t *testing.T) {
	grantToRevoke := &v2.Grant{
		Principal: &v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: userResourceType.Id,
				Resource:     "test-user",
			},
		},
		Entitlement: &v2.Entitlement{
			Resource: &v2.Resource{
				Id: &v2.ResourceId{
					ResourceType: roleResourceType.Id,
					Resource:     "role-to-revoke",
				},
			},
		},
	}

	t.Run("success", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "role-to-revoke"}}, nil, nil
			},
			UpdateUserRoleFunc: func(ctx context.Context, userID, roleID string) (annotations.Annotations, error) {
				assert.Equal(t, "test-user", userID)
				assert.Equal(t, "default-role", roleID)
				return nil, nil
			},
		}
		builder := newRoleBuilder(mockCli)
		annos, err := builder.Revoke(context.Background(), grantToRevoke)
		require.NoError(t, err)
		assert.Nil(t, annos)
	})

	t.Run("already revoked - role is default", func(t *testing.T) {
		grantToRevoke := &v2.Grant{
			Principal: &v2.Resource{
				Id: &v2.ResourceId{
					ResourceType: userResourceType.Id,
					Resource:     "test-user",
				},
			},
			Entitlement: &v2.Entitlement{
				Resource: &v2.Resource{
					Id: &v2.ResourceId{
						ResourceType: roleResourceType.Id,
						Resource:     "default-role",
					},
				},
			},
		}
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
		}
		builder := newRoleBuilder(mockCli)
		annos, err := builder.Revoke(context.Background(), grantToRevoke)
		require.NoError(t, err)
		assert.NotNil(t, annos)
		assert.True(t, hasAnnotation(annos, &v2.GrantAlreadyRevoked{}))
	})

	t.Run("already revoked - user already has default role", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "default-role"}}, nil, nil
			},
		}
		builder := newRoleBuilder(mockCli)
		annos, err := builder.Revoke(context.Background(), grantToRevoke)
		require.NoError(t, err)
		assert.NotNil(t, annos)
		assert.True(t, hasAnnotation(annos, &v2.GrantAlreadyRevoked{}))
	})

	t.Run("get default role fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "", errors.New("default role error")
			},
		}
		builder := newRoleBuilder(mockCli)
		_, err := builder.Revoke(context.Background(), grantToRevoke)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get default role")
	})

	t.Run("get policy grants fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return nil, nil, errors.New("policy error")
			},
		}
		builder := newRoleBuilder(mockCli)
		_, err := builder.Revoke(context.Background(), grantToRevoke)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get policy grants")
	})

	t.Run("update user role fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			GetDefaultRoleFunc: func(ctx context.Context) (string, error) {
				return "default-role", nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return []*client.PolicyGrant{{Subject: "test-user", Role: "role-to-revoke"}}, nil, nil
			},
			UpdateUserRoleFunc: func(ctx context.Context, userID, roleID string) (annotations.Annotations, error) {
				return nil, errors.New("update error")
			},
		}
		builder := newRoleBuilder(mockCli)
		_, err := builder.Revoke(context.Background(), grantToRevoke)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to set default role")
	})
}
