package connector

import (
	"context"
	"fmt"
	"strings"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	actionDisableUser = "disable_user"
	actionEnableUser  = "enable_user"
	actionRevokeToken = "revoke_tokens"

	argUserIDKey  = "user_id"
	retSuccessKey = "success"
)

// Account lifecycle actions must be global: C1's account-lifecycle automation looks the schemas
// up without a resource type.
var _ connectorbuilder.GlobalActionProvider = (*Connector)(nil)

var successReturnType = []*config.Field{
	{Name: retSuccessKey, DisplayName: "Success", Field: &config.Field_BoolField{BoolField: &config.BoolField{}}},
}

var disableUserSchema = &v2.BatonActionSchema{
	Name:        actionDisableUser,
	DisplayName: "Disable User",
	Description: "Disables an Argo CD local account (reversible). The account keeps its password and " +
		"API tokens, but Argo CD rejects both while the account is disabled.",
	Arguments: []*config.Field{
		{
			Name:        argUserIDKey,
			DisplayName: "User ID",
			Description: "The name of the Argo CD local account to disable.",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
			IsRequired:  true,
		},
	},
	ReturnTypes: successReturnType,
	ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT, v2.ActionType_ACTION_TYPE_ACCOUNT_DISABLE},
}

var enableUserSchema = &v2.BatonActionSchema{
	Name:        actionEnableUser,
	DisplayName: "Enable User",
	Description: "Re-enables a disabled Argo CD local account, restoring its existing password and API tokens.",
	Arguments: []*config.Field{
		{
			Name:        argUserIDKey,
			DisplayName: "User ID",
			Description: "The name of the Argo CD local account to enable.",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
			IsRequired:  true,
		},
	},
	ReturnTypes: successReturnType,
	ActionType:  []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT, v2.ActionType_ACTION_TYPE_ACCOUNT_ENABLE},
}

var revokeTokensSchema = &v2.BatonActionSchema{
	Name:        actionRevokeToken,
	DisplayName: "Revoke API Tokens",
	Description: "Revokes every API token issued to an Argo CD local account. The account itself, its " +
		"password and its enabled state are left unchanged.",
	Arguments: []*config.Field{
		{
			Name:        argUserIDKey,
			DisplayName: "User ID",
			Description: "The name of the Argo CD local account whose API tokens to revoke.",
			Field:       &config.Field_StringField{StringField: &config.StringField{}},
			IsRequired:  true,
		},
	},
	ReturnTypes: successReturnType,
	// There is no dedicated revoke action type; the base account type keeps it an account action.
	ActionType: []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT},
}

// GlobalActions registers the enable_user, disable_user and revoke_tokens account actions.
func (c *Connector) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, disableUserSchema, c.disableUser); err != nil {
		return fmt.Errorf("baton-argo-cd: failed to register %s action: %w", actionDisableUser, err)
	}
	if err := registry.Register(ctx, enableUserSchema, c.enableUser); err != nil {
		return fmt.Errorf("baton-argo-cd: failed to register %s action: %w", actionEnableUser, err)
	}
	if err := registry.Register(ctx, revokeTokensSchema, c.revokeTokens); err != nil {
		return fmt.Errorf("baton-argo-cd: failed to register %s action: %w", actionRevokeToken, err)
	}
	return nil
}

func (c *Connector) disableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return c.setUserEnabled(ctx, args, false)
}

func (c *Connector) enableUser(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	return c.setUserEnabled(ctx, args, true)
}

// setUserEnabled backs both lifecycle actions. An account already in the requested state is
// reported as success.
func (c *Connector) setUserEnabled(ctx context.Context, args *structpb.Struct, enabled bool) (*structpb.Struct, annotations.Annotations, error) {
	username, err := usernameFromArgs(args)
	if err != nil {
		return nil, nil, err
	}

	if err := c.client.SetAccountEnabled(ctx, username, enabled); err != nil {
		return nil, nil, accountActionError(err, fmt.Sprintf("set enabled=%t on", enabled), username)
	}

	ctxzap.Extract(ctx).Info("Updated Argo CD local account state",
		zap.String("account", username),
		zap.Bool("enabled", enabled),
	)

	return successStruct(), nil, nil
}

// revokeTokens revokes every API token issued to an account. Tokens that are already revoked are
// skipped, so an account with no tokens left is reported as success.
func (c *Connector) revokeTokens(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	username, err := usernameFromArgs(args)
	if err != nil {
		return nil, nil, err
	}

	if err := c.client.RevokeAccountTokens(ctx, username); err != nil {
		return nil, nil, accountActionError(err, "revoke API tokens of", username)
	}

	ctxzap.Extract(ctx).Info("Revoked Argo CD local account API tokens", zap.String("account", username))

	return successStruct(), nil, nil
}

// usernameFromArgs extracts the target account name shared by every account action.
func usernameFromArgs(args *structpb.Struct) (string, error) {
	userID, err := actions.RequireStringArg(args, argUserIDKey)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "baton-argo-cd: %v", err)
	}
	username := strings.TrimSpace(userID)
	if username == "" {
		return "", status.Errorf(codes.InvalidArgument, "baton-argo-cd: %s must not be empty", argUserIDKey)
	}
	return username, nil
}

// accountActionError wraps a client error for an account action. Client errors carry the gRPC
// code for their cause (NotFound for an unknown account, InvalidArgument for a protected or
// malformed one, the mapped code for an API failure), and wrapping with %w preserves it.
func accountActionError(err error, operation string, username string) error {
	return fmt.Errorf("baton-argo-cd: failed to %s account %q: %w", operation, username, err)
}

func successStruct() *structpb.Struct {
	return &structpb.Struct{
		Fields: map[string]*structpb.Value{
			retSuccessKey: structpb.NewBoolValue(true),
		},
	}
}
