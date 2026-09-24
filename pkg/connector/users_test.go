package connector

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-argo-cd/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

		builder := newUserBuilder(mockCli)
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
		builder := newUserBuilder(nil)
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

		builder := newUserBuilder(mockCli)
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

// TestUserBuilder_Delete verifies the hard-delete sequence: tokens are revoked through the API,
// RBAC policies are removed from argocd-rbac-cm, the account entry is removed from argocd-cm, and
// stored credentials are purged -- in that order.
func TestUserBuilder_Delete(t *testing.T) {
	var calls []string
	mockCli := &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "revoke-tokens")
			return nil
		},
		SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
			calls = append(calls, "set-enabled")
			return nil
		},
		RemoveAccountPoliciesFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "remove-policies")
			return nil
		},
		DeleteAccountFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "delete")
			return nil
		},
		PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
			assert.Equal(t, "alice", username)
			calls = append(calls, "purge-credentials")
			return nil
		},
	}

	builder := newUserBuilder(mockCli)
	annos, err := builder.Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     " alice ",
	})
	require.NoError(t, err)
	assert.Nil(t, annos)
	assert.Equal(t, []string{"revoke-tokens", "remove-policies", "delete", "purge-credentials"}, calls)
}

// TestUserBuilder_Delete_Validation verifies malformed targets are rejected before any client call.
func TestUserBuilder_Delete_Validation(t *testing.T) {
	failOnCall := func(ctx context.Context, username string) error {
		t.Fatalf("unexpected client call for %q", username)
		return nil
	}
	mockCli := &test.MockClient{
		RevokeAccountTokensFunc:     failOnCall,
		RemoveAccountPoliciesFunc:   failOnCall,
		DeleteAccountFunc:           failOnCall,
		PurgeAccountCredentialsFunc: failOnCall,
	}
	builder := newUserBuilder(mockCli)

	t.Run("wrong resource type", func(t *testing.T) {
		_, err := builder.Delete(context.Background(), &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "alice"})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "cannot delete resource type")
	})

	t.Run("empty resource id", func(t *testing.T) {
		_, err := builder.Delete(context.Background(), &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "  "})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, err.Error(), "resource id is empty")
	})
}

// TestUserBuilder_Delete_PropagatesErrors verifies a failing step aborts the delete with a wrapped
// error and skips the later steps.
func TestUserBuilder_Delete_PropagatesErrors(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name      string
		failStep  string
		wantMsg   string
		wantCalls []string
	}{
		{"token revocation fails", "revoke-tokens", "failed to revoke API tokens", []string{"revoke-tokens"}},
		{"policy removal fails", "remove-policies", "failed to remove RBAC policies", []string{"revoke-tokens", "remove-policies"}},
		{"delete fails", "delete", "failed to delete account", []string{"revoke-tokens", "remove-policies", "delete"}},
		{"credential purge fails", "purge-credentials", "failed to purge stored credentials", []string{"revoke-tokens", "remove-policies", "delete", "purge-credentials"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			step := func(name string) func(context.Context, string) error {
				return func(ctx context.Context, username string) error {
					calls = append(calls, name)
					if name == tt.failStep {
						return boom
					}
					return nil
				}
			}
			mockCli := &test.MockClient{
				RevokeAccountTokensFunc:     step("revoke-tokens"),
				RemoveAccountPoliciesFunc:   step("remove-policies"),
				DeleteAccountFunc:           step("delete"),
				PurgeAccountCredentialsFunc: step("purge-credentials"),
			}

			_, err := newUserBuilder(mockCli).Delete(context.Background(), &v2.ResourceId{
				ResourceType: userResourceType.Id,
				Resource:     "alice",
			})
			require.ErrorIs(t, err, boom)
			assert.Contains(t, err.Error(), tt.wantMsg)
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}

// TestUserBuilder_Delete_AccountUnknownToAPI verifies an account Argo CD no longer resolves does
// not block the rest of the delete, so stale RBAC policies, argocd-cm and argocd-secret entries
// still get cleaned.
func TestUserBuilder_Delete_AccountUnknownToAPI(t *testing.T) {
	var calls []string
	mockCli := &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "revoke-tokens")
			return uhttp.WrapErrors(codes.NotFound, "not found", fmt.Errorf("%w: %s", client.ErrAccountNotFound, username))
		},
		RemoveAccountPoliciesFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "remove-policies")
			return nil
		},
		DeleteAccountFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "delete")
			return nil
		},
		PurgeAccountCredentialsFunc: func(ctx context.Context, username string) error {
			calls = append(calls, "purge-credentials")
			return nil
		},
	}

	_, err := newUserBuilder(mockCli).Delete(context.Background(), &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"revoke-tokens", "remove-policies", "delete", "purge-credentials"}, calls)
}

func randomPasswordOptions(length int64) *v2.LocalCredentialOptions {
	return &v2.LocalCredentialOptions{
		Options: &v2.LocalCredentialOptions_RandomPassword_{
			RandomPassword: &v2.LocalCredentialOptions_RandomPassword{Length: length},
		},
	}
}

// TestUserBuilder_Rotate verifies a random password is generated, set on the trimmed account name,
// and returned for the vault.
func TestUserBuilder_Rotate(t *testing.T) {
	var gotUser, gotPassword string
	mockCli := &test.MockClient{
		RotateAccountPasswordFunc: func(ctx context.Context, username string, password string) error {
			gotUser, gotPassword = username, password
			return nil
		},
	}

	plaintexts, annos, err := newUserBuilder(mockCli).Rotate(context.Background(),
		&v2.ResourceId{ResourceType: userResourceType.Id, Resource: " alice "},
		randomPasswordOptions(20),
	)
	require.NoError(t, err)
	assert.Nil(t, annos)
	assert.Equal(t, "alice", gotUser)
	require.Len(t, plaintexts, 1)
	assert.Equal(t, "password", plaintexts[0].GetName())
	assert.Equal(t, gotPassword, string(plaintexts[0].GetBytes()))
	assert.Len(t, gotPassword, 20)
}

// TestUserBuilder_Rotate_Validation verifies bad targets and unsupported credential options are
// rejected before the client is called.
func TestUserBuilder_Rotate_Validation(t *testing.T) {
	mockCli := &test.MockClient{
		RotateAccountPasswordFunc: func(ctx context.Context, username string, password string) error {
			t.Fatalf("unexpected client call for %q", username)
			return nil
		},
	}
	builder := newUserBuilder(mockCli)
	userID := &v2.ResourceId{ResourceType: userResourceType.Id, Resource: "alice"}

	tests := []struct {
		name    string
		id      *v2.ResourceId
		opts    *v2.LocalCredentialOptions
		wantMsg string
	}{
		{"wrong resource type", &v2.ResourceId{ResourceType: roleResourceType.Id, Resource: "alice"}, randomPasswordOptions(20), "cannot rotate credentials of resource type"},
		{"empty resource id", &v2.ResourceId{ResourceType: userResourceType.Id, Resource: " "}, randomPasswordOptions(20), "resource id is empty"},
		{"no credential options", userID, nil, "failed to generate password"},
		{"unsupported credential option", userID, &v2.LocalCredentialOptions{
			Options: &v2.LocalCredentialOptions_NoPassword_{NoPassword: &v2.LocalCredentialOptions_NoPassword{}},
		}, "failed to generate password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := builder.Rotate(context.Background(), tt.id, tt.opts)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

// TestUserBuilder_Rotate_PropagatesErrors verifies a failed password update is returned wrapped.
func TestUserBuilder_Rotate_PropagatesErrors(t *testing.T) {
	boom := errors.New("boom")
	mockCli := &test.MockClient{
		RotateAccountPasswordFunc: func(ctx context.Context, username string, password string) error {
			return boom
		},
	}

	_, _, err := newUserBuilder(mockCli).Rotate(context.Background(),
		&v2.ResourceId{ResourceType: userResourceType.Id, Resource: "alice"},
		randomPasswordOptions(20),
	)
	require.ErrorIs(t, err, boom)
	assert.Contains(t, err.Error(), "failed to rotate password")
}

// TestUserBuilder_Rotate_KeepsClientErrorCode verifies a client error reaches C1 with its gRPC code
// and typed cause intact, so an unknown or protected account is not retried as a transient failure.
func TestUserBuilder_Rotate_KeepsClientErrorCode(t *testing.T) {
	for name, tt := range map[string]struct {
		code  codes.Code
		cause error
	}{
		"unknown account":   {codes.NotFound, client.ErrAccountNotFound},
		"protected account": {codes.InvalidArgument, client.ErrInvalidAccountTarget},
	} {
		t.Run(name, func(t *testing.T) {
			mockCli := &test.MockClient{
				RotateAccountPasswordFunc: func(ctx context.Context, username string, password string) error {
					return uhttp.WrapErrors(tt.code, "client error", fmt.Errorf("%w: %s", tt.cause, username))
				},
			}

			_, _, err := newUserBuilder(mockCli).Rotate(context.Background(),
				&v2.ResourceId{ResourceType: userResourceType.Id, Resource: "alice"},
				randomPasswordOptions(20),
			)
			assert.Equal(t, tt.code, status.Code(err))
			require.ErrorIs(t, err, tt.cause)
		})
	}
}
