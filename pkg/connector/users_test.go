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
	"google.golang.org/protobuf/types/known/structpb"
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

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
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

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		_, _, _, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch user data")
	})
}

// TestUserBuilder_Entitlements tests the Entitlements method.
func TestUserBuilder_Entitlements(t *testing.T) {
	builder := newUserBuilder(nil, client.DeprovisionModeDisable)
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
	builder := newUserBuilder(nil, client.DeprovisionModeDisable)
	resource := &v2.Resource{
		Id: &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "test-user"},
	}

	grants, nextPage, annos, err := builder.Grants(context.Background(), resource, &pagination.Token{})
	require.NoError(t, err)
	assert.Empty(t, nextPage)
	assert.Nil(t, annos)
	assert.Empty(t, grants)
}

// TestUserBuilder_CreateAccountCapabilityDetails tests capability details.
func TestUserBuilder_CreateAccountCapabilityDetails(t *testing.T) {
	builder := newUserBuilder(nil, client.DeprovisionModeDisable)

	details, annos, err := builder.CreateAccountCapabilityDetails(context.Background())
	require.NoError(t, err)
	require.NotNil(t, details)
	assert.Nil(t, annos)

	assert.Contains(t, details.SupportedCredentialOptions, v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD)
	assert.Equal(t, v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD, details.PreferredCredentialOption)
}

// TestUserBuilder_CreateAccount tests account creation.
func TestUserBuilder_CreateAccount(t *testing.T) {
	t.Run("success with login", func(t *testing.T) {
		mockCli := &test.MockClient{
			CreateAccountFunc: func(ctx context.Context, username string, password string) (*client.Account, annotations.Annotations, error) {
				assert.Equal(t, "test-user", username)
				assert.NotEmpty(t, password)
				return &client.Account{
					Name:         username,
					Enabled:      true,
					Capabilities: []string{"apiKey", "login"},
				}, nil, nil
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		accountInfo := &v2.AccountInfo{
			Login: "test-user",
		}
		credentialOptions := &v2.LocalCredentialOptions{}
		credentialOptions.SetRandomPassword(&v2.LocalCredentialOptions_RandomPassword{
			Length: 16,
		})

		resp, plaintextData, _, err := builder.CreateAccount(context.Background(), accountInfo, credentialOptions)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, plaintextData, 1)
		assert.Equal(t, "password", plaintextData[0].Name)
		assert.NotEmpty(t, plaintextData[0].Bytes)
	})

	t.Run("error missing username", func(t *testing.T) {
		builder := newUserBuilder(nil, client.DeprovisionModeDisable)
		accountInfo := &v2.AccountInfo{
			Profile: createProfile(map[string]interface{}{
				"email": "test@example.com",
			}),
		}
		credentialOptions := &v2.LocalCredentialOptions{}
		credentialOptions.SetRandomPassword(&v2.LocalCredentialOptions_RandomPassword{
			Length: 16,
		})

		_, _, _, err := builder.CreateAccount(context.Background(), accountInfo, credentialOptions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("error client create fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			CreateAccountFunc: func(ctx context.Context, username string, password string) (*client.Account, annotations.Annotations, error) {
				return nil, nil, errors.New("create account failed")
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		accountInfo := &v2.AccountInfo{
			Login: "test-user",
		}
		credentialOptions := &v2.LocalCredentialOptions{}
		credentialOptions.SetRandomPassword(&v2.LocalCredentialOptions_RandomPassword{
			Length: 16,
		})

		_, _, _, err := builder.CreateAccount(context.Background(), accountInfo, credentialOptions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create user")
	})
}

// TestUserBuilder_ExtractUsername tests the extractUsername method.
func TestUserBuilder_ExtractUsername(t *testing.T) {
	builder := &userBuilder{}

	t.Run("extract from login field", func(t *testing.T) {
		accountInfo := &v2.AccountInfo{
			Login: "login-user",
		}
		result, err := builder.extractUsername(accountInfo)
		assert.NoError(t, err)
		assert.Equal(t, "login-user", result)
	})

	t.Run("extract from profile username", func(t *testing.T) {
		accountInfo := &v2.AccountInfo{
			Profile: createProfile(map[string]interface{}{
				"username": "profile-user",
			}),
		}
		result, err := builder.extractUsername(accountInfo)
		assert.NoError(t, err)
		assert.Equal(t, "profile-user", result)
	})

	t.Run("error no username", func(t *testing.T) {
		accountInfo := &v2.AccountInfo{
			Profile: createProfile(map[string]interface{}{
				"email": "test@example.com",
			}),
		}
		_, err := builder.extractUsername(accountInfo)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username is required")
	})
}

// Helper function to create a structpb.Struct from a map.
func createProfile(data map[string]interface{}) *structpb.Struct {
	profile, _ := structpb.NewStruct(data)
	return profile
}

// TestUserBuilder_Delete_DisableMode verifies the disable-mode deprovision sequence: tokens are
// revoked through the API, the account entry is disabled (not deleted), and stored credentials
// are purged.
func TestUserBuilder_Delete_DisableMode(t *testing.T) {
	var calls []string
	mockCli := &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "revoke-tokens")
			return nil
		},
		DisableAccountFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "disable")
			return nil
		},
		DeleteAccountFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "delete")
			return nil
		},
		PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "purge-credentials")
			return nil
		},
	}

	builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
	annos, err := builder.Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     "alice",
	})
	require.NoError(t, err)
	assert.Nil(t, annos)

	// Tokens must be revoked while the account is still resolvable through the Argo CD API, and
	// credentials purged only after the account entry is gone.
	assert.Equal(t, []string{"revoke-tokens", "disable", "purge-credentials"}, calls)
}

// TestUserBuilder_Delete_DeleteMode verifies delete mode removes the account entry instead of
// disabling it.
func TestUserBuilder_Delete_DeleteMode(t *testing.T) {
	var calls []string
	mockCli := &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "revoke-tokens")
			return nil
		},
		DisableAccountFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "disable")
			return nil
		},
		DeleteAccountFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "delete")
			return nil
		},
		PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "purge-credentials")
			return nil
		},
	}

	builder := newUserBuilder(mockCli, client.DeprovisionModeDelete)
	_, err := builder.Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"revoke-tokens", "delete", "purge-credentials"}, calls)
}

// TestUserBuilder_Delete_DefaultsToDisable verifies an unset mode falls back to the reversible
// disable behaviour.
func TestUserBuilder_Delete_DefaultsToDisable(t *testing.T) {
	var disabled bool
	mockCli := &test.MockClient{
		DisableAccountFunc: func(ctx context.Context, username string) error {
			disabled = true
			return nil
		},
		DeleteAccountFunc: func(ctx context.Context, username string) error {
			t.Fatal("delete must not be used when no deprovision mode is configured")
			return nil
		},
	}

	builder := newUserBuilder(mockCli, "")
	_, err := builder.Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     "alice",
	})
	require.NoError(t, err)
	assert.True(t, disabled)
	assert.Equal(t, client.DeprovisionModeDisable, builder.deprovisionMode)
}

// TestUserBuilder_Delete_TrimsResourceID verifies surrounding whitespace in the resource id does
// not leak into the account name used for API and ConfigMap operations.
func TestUserBuilder_Delete_TrimsResourceID(t *testing.T) {
	mockCli := &test.MockClient{
		DisableAccountFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			return nil
		},
	}

	builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
	_, err := builder.Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     "  alice  ",
	})
	require.NoError(t, err)
}

// TestUserBuilder_Delete_Validation covers rejected delete requests.
func TestUserBuilder_Delete_Validation(t *testing.T) {
	t.Run("wrong resource type", func(t *testing.T) {
		builder := newUserBuilder(&test.MockClient{}, client.DeprovisionModeDisable)
		_, err := builder.Delete(context.Background(), &v2.ResourceId{
			ResourceType: roleResourceType.Id,
			Resource:     "developers",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot deprovision resource type")
	})

	t.Run("empty resource id", func(t *testing.T) {
		builder := newUserBuilder(&test.MockClient{}, client.DeprovisionModeDisable)
		_, err := builder.Delete(context.Background(), &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     "   ",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resource id is empty")
	})

	t.Run("unsupported mode", func(t *testing.T) {
		builder := &userBuilder{
			resourceType:    userResourceType,
			client:          &test.MockClient{},
			deprovisionMode: client.DeprovisionMode("purge"),
		}
		_, err := builder.Delete(context.Background(), &v2.ResourceId{
			ResourceType: userResourceType.Id,
			Resource:     "alice",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported deprovision mode")
	})
}

// TestUserBuilder_Delete_PropagatesErrors verifies a failure in any step aborts the deprovision
// with a wrapped error instead of silently continuing.
func TestUserBuilder_Delete_PropagatesErrors(t *testing.T) {
	resourceID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "alice"}

	t.Run("token revocation fails", func(t *testing.T) {
		var disableCalled bool
		mockCli := &test.MockClient{
			RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
				return errors.New("permission denied")
			},
			DisableAccountFunc: func(ctx context.Context, username string) error {
				disableCalled = true
				return nil
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		_, err := builder.Delete(context.Background(), resourceID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to revoke API tokens")
		assert.False(t, disableCalled, "the account must not be disabled when token revocation failed")
	})

	t.Run("disable fails", func(t *testing.T) {
		var purgeCalled bool
		mockCli := &test.MockClient{
			DisableAccountFunc: func(ctx context.Context, username string) error {
				return errors.New("configmap patch rejected")
			},
			PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
				purgeCalled = true
				return nil
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		_, err := builder.Delete(context.Background(), resourceID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to disable account")
		assert.False(t, purgeCalled)
	})

	t.Run("delete fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			DeleteAccountFunc: func(ctx context.Context, username string) error {
				return errors.New("configmap patch rejected")
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDelete)
		_, err := builder.Delete(context.Background(), resourceID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete account")
	})

	t.Run("credential purge fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
				return errors.New("secret patch rejected")
			},
		}

		builder := newUserBuilder(mockCli, client.DeprovisionModeDisable)
		_, err := builder.Delete(context.Background(), resourceID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to purge stored credentials")
	})
}
