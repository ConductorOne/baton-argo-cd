package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
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
// This includes both real user accounts from ArgoCD and external subjects from policy grants.
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

// newUserBuilder creates a new userBuilder instance.
func newUserBuilder(client ArgoCdClient) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
	}
}
