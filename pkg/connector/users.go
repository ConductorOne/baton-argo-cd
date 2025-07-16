package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

// userBuilder implements the ResourceSyncer and AccountManager interfaces for Argo CD users.
type userBuilder struct {
	resourceType *v2.ResourceType
	client       ArgoCdClient
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
	credentialOptions *v2.CredentialOptions,
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

// newUserBuilder creates a new userBuilder instance.
func newUserBuilder(client ArgoCdClient) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
	}
}
