package connector

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-argo-cd/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func userIDArgs(t *testing.T, userID any) *structpb.Struct {
	t.Helper()
	args, err := structpb.NewStruct(map[string]any{argUserIDKey: userID})
	require.NoError(t, err)
	return args
}

// TestGlobalActions_Registered verifies every account action is exposed as a global action with
// the account action types C1's automation routes on.
func TestGlobalActions_Registered(t *testing.T) {
	ctx := context.Background()

	server, err := connectorbuilder.NewConnector(ctx, &Connector{client: &test.MockClient{}})
	require.NoError(t, err)

	resp, err := server.ListActionSchemas(ctx, &v2.ListActionSchemasRequest{})
	require.NoError(t, err)

	schemas := map[string]*v2.BatonActionSchema{}
	for _, schema := range resp.GetSchemas() {
		schemas[schema.GetName()] = schema
	}

	for name, actionTypes := range map[string][]v2.ActionType{
		actionDisableUser: {v2.ActionType_ACTION_TYPE_ACCOUNT, v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE},
		actionEnableUser:  {v2.ActionType_ACTION_TYPE_ACCOUNT, v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE},
		actionRevokeToken: {v2.ActionType_ACTION_TYPE_ACCOUNT},
	} {
		schema, ok := schemas[name]
		require.True(t, ok, "action %q not registered", name)
		assert.Empty(t, schema.GetResourceTypeId(), "account action %q must be global", name)
		assert.ElementsMatch(t, actionTypes, schema.GetActionType())
		require.Len(t, schema.GetArguments(), 1)
		assert.Equal(t, argUserIDKey, schema.GetArguments()[0].GetName())
		assert.True(t, schema.GetArguments()[0].GetIsRequired())
	}
}

// TestSetUserEnabled_Success verifies each action sets the matching state on the trimmed account
// name and reports success.
func TestSetUserEnabled_Success(t *testing.T) {
	for name, want := range map[string]bool{actionDisableUser: false, actionEnableUser: true} {
		t.Run(name, func(t *testing.T) {
			var gotUser string
			var gotEnabled *bool
			c := &Connector{client: &test.MockClient{
				SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
					gotUser, gotEnabled = username, &enabled
					return nil
				},
			}}

			handler := c.disableUser
			if want {
				handler = c.enableUser
			}

			result, annos, err := handler(context.Background(), userIDArgs(t, " alice "))
			require.NoError(t, err)
			assert.Nil(t, annos)
			assert.True(t, result.GetFields()[retSuccessKey].GetBoolValue())
			assert.Equal(t, "alice", gotUser)
			require.NotNil(t, gotEnabled)
			assert.Equal(t, want, *gotEnabled)
		})
	}
}

// TestSetUserEnabled_InvalidArguments verifies missing or empty user ids are rejected with
// InvalidArgument before reaching the client.
func TestSetUserEnabled_InvalidArguments(t *testing.T) {
	c := &Connector{client: &test.MockClient{
		SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
			t.Fatalf("unexpected client call for %q", username)
			return nil
		},
	}}

	for name, args := range map[string]*structpb.Struct{
		"nil args":      nil,
		"missing":       {Fields: map[string]*structpb.Value{}},
		"wrong type":    userIDArgs(t, 42),
		"blank user id": userIDArgs(t, "   "),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := c.disableUser(context.Background(), args)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// TestSetUserEnabled_ErrorMapping verifies client errors surface with the matching gRPC code.
func TestSetUserEnabled_ErrorMapping(t *testing.T) {
	boom := errors.New("boom")

	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{"account not found", fmt.Errorf("%w: alice", client.ErrAccountNotFound), codes.NotFound},
		{"protected or malformed account", fmt.Errorf("%w: refusing", client.ErrInvalidAccountTarget), codes.InvalidArgument},
		{"other failure", boom, codes.Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{client: &test.MockClient{
				SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
					return tt.err
				},
			}}

			_, _, err := c.enableUser(context.Background(), userIDArgs(t, "alice"))
			require.Error(t, err)
			assert.Equal(t, tt.wantCode, status.Code(err))

			_, _, err = c.disableUser(context.Background(), userIDArgs(t, "alice"))
			require.Error(t, err)
			assert.Equal(t, tt.wantCode, status.Code(err))
		})

		t.Run(tt.name+"/revoke_tokens", func(t *testing.T) {
			c := &Connector{client: &test.MockClient{
				RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
					return tt.err
				},
			}}

			_, _, err := c.revokeTokens(context.Background(), userIDArgs(t, "alice"))
			require.Error(t, err)
			assert.Equal(t, tt.wantCode, status.Code(err))
		})
	}

	t.Run("other failure is wrapped", func(t *testing.T) {
		c := &Connector{client: &test.MockClient{
			SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
				return boom
			},
		}}
		_, _, err := c.disableUser(context.Background(), userIDArgs(t, "alice"))
		require.ErrorIs(t, err, boom)
	})
}

// TestRevokeTokens_Success verifies the action revokes the trimmed account's tokens and reports
// success.
func TestRevokeTokens_Success(t *testing.T) {
	var gotUser string
	c := &Connector{client: &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			gotUser = username
			return nil
		},
		SetAccountEnabledFunc: func(ctx context.Context, username string, enabled bool) error {
			t.Fatalf("revoke_tokens must not change the account's enabled state")
			return nil
		},
	}}

	result, annos, err := c.revokeTokens(context.Background(), userIDArgs(t, " alice "))
	require.NoError(t, err)
	assert.Nil(t, annos)
	assert.True(t, result.GetFields()[retSuccessKey].GetBoolValue())
	assert.Equal(t, "alice", gotUser)
}

// TestRevokeTokens_InvalidArguments verifies revoke_tokens shares the argument validation of the
// lifecycle actions.
func TestRevokeTokens_InvalidArguments(t *testing.T) {
	c := &Connector{client: &test.MockClient{
		RevokeAccountTokensFunc: func(ctx context.Context, username string) error {
			t.Fatalf("unexpected client call for %q", username)
			return nil
		},
	}}

	for name, args := range map[string]*structpb.Struct{
		"nil args":      nil,
		"blank user id": userIDArgs(t, " "),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := c.revokeTokens(context.Background(), args)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}
