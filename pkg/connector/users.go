package connector

import (
	"context"
	"fmt"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// Compile-time assertions that userBuilder still satisfies the SDK interfaces it is registered
// for. The SDK discovers capabilities by type assertion, so a drifting method signature would
// otherwise silently drop account provisioning or deprovisioning from the connector.
var (
	_ connectorbuilder.ResourceSyncer  = (*userBuilder)(nil)
	_ connectorbuilder.AccountManager  = (*userBuilder)(nil)
	_ connectorbuilder.ResourceDeleter = (*userBuilder)(nil)
)

// userBuilder implements the ResourceSyncer, AccountManager and ResourceDeleter interfaces for
// Argo CD users.
type userBuilder struct {
	resourceType *v2.ResourceType
	client       ArgoCdClient
	// deprovisionMode decides whether Delete disables or removes the local account entry.
	deprovisionMode client.DeprovisionMode
}

// ResourceType returns the resource type for users.
func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all users from Argo CD as resource objects.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	accounts, err := u.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to fetch user data: %w", err)
	}

	var resources []*v2.Resource
	for _, account := range accounts {
		accountResource, err := parseAccountResource(account)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to parse account %s: %w", account.Name, err)
		}
		resources = append(resources, accountResource)
	}
	return resources, "", nil, nil
}

// Entitlements returns an empty slice as users don't have entitlements.
func (u *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants returns an empty slice as users don't have grants in this implementation.
func (u *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// CreateAccountCapabilityDetails declares support for account provisioning with random password generation.
func (u *userBuilder) CreateAccountCapabilityDetails(ctx context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_RANDOM_PASSWORD,
	}, nil, nil
}

// CreateAccount provisions a new Argo CD user based on AccountInfo and CredentialOptions.
func (u *userBuilder) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	username, err := u.extractUsername(accountInfo)
	if err != nil {
		return nil, nil, nil, err
	}

	password, err := generateCredentials(credentialOptions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate password: %w", err)
	}

	newUser, annos, err := u.client.CreateAccount(ctx, username, password)
	if err != nil {
		return nil, nil, annos, fmt.Errorf("failed to create user: %w", err)
	}

	userResource, err := parseAccountResource(newUser)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse created user: %w", err)
	}

	passwordResult := &v2.PlaintextData{
		Name:  "password",
		Bytes: []byte(password),
	}

	return &v2.CreateAccountResponse_SuccessResult{
		Resource: userResource,
	}, []*v2.PlaintextData{passwordResult}, annos, nil
}

// Delete deprovisions an Argo CD local account, closing the leaver half of the account lifecycle.
//
// Argo CD's Account REST API has no delete or disable endpoint, so the account entry is changed
// through the Kubernetes API against `argocd-cm`. Deprovisioning runs in three steps, in this order:
//
//  1. Revoke the account's issued API tokens through the Argo CD API. This is the only immediate
//     revocation path, and it needs the account to still be resolvable through the API.
//  2. Disable or delete the `accounts.<name>` entry in `argocd-cm`, per the configured mode.
//  3. Purge the account's stored credentials (password hash and token records) from `argocd-secret`,
//     so no residual access path survives the account.
//
// Each step treats an already-deprovisioned state as success, so a retried deprovision converges
// instead of failing.
func (u *userBuilder) Delete(ctx context.Context, resourceId *v2.ResourceId) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if rt := resourceId.GetResourceType(); rt != userResourceType.Id {
		return nil, fmt.Errorf(
			"baton-argo-cd: cannot deprovision resource type %q: only %q resources can be deprovisioned",
			rt, userResourceType.Id,
		)
	}

	username := strings.TrimSpace(resourceId.GetResource())
	if username == "" {
		return nil, fmt.Errorf("baton-argo-cd: cannot deprovision account: resource id is empty")
	}

	if err := u.client.RevokeAccountTokens(ctx, username); err != nil {
		return nil, fmt.Errorf("baton-argo-cd: failed to revoke API tokens for account %q: %w", username, err)
	}

	switch u.deprovisionMode {
	case client.DeprovisionModeDelete:
		if err := u.client.DeleteAccount(ctx, username); err != nil {
			return nil, fmt.Errorf("baton-argo-cd: failed to delete account %q: %w", username, err)
		}
	case client.DeprovisionModeDisable:
		if err := u.client.DisableAccount(ctx, username); err != nil {
			return nil, fmt.Errorf("baton-argo-cd: failed to disable account %q: %w", username, err)
		}
	default:
		return nil, fmt.Errorf(
			"baton-argo-cd: unsupported deprovision mode %q: must be %q or %q",
			u.deprovisionMode, client.DeprovisionModeDisable, client.DeprovisionModeDelete,
		)
	}

	if err := u.client.PurgeAccountCredentials(ctx, username); err != nil {
		return nil, fmt.Errorf("baton-argo-cd: failed to purge stored credentials for account %q: %w", username, err)
	}

	l.Info("Deprovisioned Argo CD local account",
		zap.String("account", username),
		zap.String("deprovision_mode", string(u.deprovisionMode)),
	)

	return nil, nil
}

// extractUsername safely retrieves the username from the AccountInfo protobuf message.
// It prioritizes the `login` field and falls back to profile information,
// ensuring that a valid, non-empty username is returned.
func (u *userBuilder) extractUsername(accountInfo *v2.AccountInfo) (string, error) {
	if login := accountInfo.GetLogin(); login != "" {
		return strings.TrimSpace(login), nil
	}

	profile := accountInfo.GetProfile().AsMap()

	if username, ok := profile["username"].(string); ok && strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username), nil
	}

	if login, ok := profile["login"].(string); ok && strings.TrimSpace(login) != "" {
		return strings.TrimSpace(login), nil
	}

	return "", fmt.Errorf("username is required")
}

// newUserBuilder creates a new userBuilder instance. An empty deprovisionMode selects the
// default, client.DeprovisionModeDisable.
func newUserBuilder(cli ArgoCdClient, deprovisionMode client.DeprovisionMode) *userBuilder {
	if deprovisionMode == "" {
		deprovisionMode = client.DeprovisionModeDisable
	}
	return &userBuilder{
		resourceType:    userResourceType,
		client:          cli,
		deprovisionMode: deprovisionMode,
	}
}
