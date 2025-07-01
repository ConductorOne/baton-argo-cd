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
		mockGrants := []*client.PolicyGrant{
			{Subject: "user3", Role: "role1"},
		}
		mockCli := &test.MockClient{
			GetAccountsFunc: func(ctx context.Context) ([]*client.Account, error) {
				return mockAccounts, nil
			},
			GetPolicyGrantsFunc: func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
				return mockGrants, nil, nil
			},
		}

		builder := newUserBuilder(mockCli)
		resources, nextPage, annos, err := builder.List(context.Background(), nil, &pagination.Token{})
		require.NoError(t, err)
		assert.Empty(t, nextPage)
		assert.Nil(t, annos)
		assert.Len(t, resources, 3)
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
		Id: &v2.ResourceId{ResourceType: accountResourceType.Id, Resource: "test-user"},
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
		Id: &v2.ResourceId{ResourceType: accountResourceType.Id, Resource: "test-user"},
	}

	grants, nextPage, annos, err := builder.Grants(context.Background(), resource, &pagination.Token{})
	require.NoError(t, err)
	assert.Empty(t, nextPage)
	assert.Nil(t, annos)
	assert.Empty(t, grants)
}

// TestUserBuilder_CreateAccountCapabilityDetails tests capability details.
func TestUserBuilder_CreateAccountCapabilityDetails(t *testing.T) {
	builder := newUserBuilder(nil)

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
			CreateAccountFunc: func(ctx context.Context, username string, email string, password string) (*client.Account, annotations.Annotations, error) {
				return &client.Account{
					Name:         username,
					Enabled:      true,
					Capabilities: []string{"apiKey", "login"},
				}, nil, nil
			},
		}

		builder := newUserBuilder(mockCli)
		accountInfo := &v2.AccountInfo{
			Login: "test-user",
		}
		credentialOptions := &v2.CredentialOptions{
			Options: &v2.CredentialOptions_RandomPassword_{
				RandomPassword: &v2.CredentialOptions_RandomPassword{
					Length: 16,
				},
			},
		}

		resp, plaintextData, _, err := builder.CreateAccount(context.Background(), accountInfo, credentialOptions)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, plaintextData, 1)
		assert.Equal(t, "password", plaintextData[0].Name)
		assert.NotEmpty(t, plaintextData[0].Bytes)
	})

	t.Run("error missing username", func(t *testing.T) {
		builder := newUserBuilder(nil)
		accountInfo := &v2.AccountInfo{
			Profile: createProfile(map[string]interface{}{
				"email": "test@example.com",
			}),
		}
		credentialOptions := &v2.CredentialOptions{
			Options: &v2.CredentialOptions_RandomPassword_{
				RandomPassword: &v2.CredentialOptions_RandomPassword{
					Length: 16,
				},
			},
		}

		_, _, _, err := builder.CreateAccount(context.Background(), accountInfo, credentialOptions)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("error client create fails", func(t *testing.T) {
		mockCli := &test.MockClient{
			CreateAccountFunc: func(ctx context.Context, username string, email string, password string) (*client.Account, annotations.Annotations, error) {
				return nil, nil, errors.New("create account failed")
			},
		}

		builder := newUserBuilder(mockCli)
		accountInfo := &v2.AccountInfo{
			Login: "test-user",
		}
		credentialOptions := &v2.CredentialOptions{
			Options: &v2.CredentialOptions_RandomPassword_{
				RandomPassword: &v2.CredentialOptions_RandomPassword{
					Length: 16,
				},
			},
		}

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

// Helper function to create a structpb.Struct from a map
func createProfile(data map[string]interface{}) *structpb.Struct {
	profile, _ := structpb.NewStruct(data)
	return profile
}
