package connector

import (
	"context"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
)

type userBuilder struct {
	resourceType *v2.ResourceType
	client       ArgoCdClient
}

func (o *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

// List returns all the users from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard user.
func (o *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	accountsMap, policyGrants, annos, err := getAllUserData(ctx, o.client)
	if err != nil {
		return nil, "", annos, err
	}

	var resources []*v2.Resource
	for _, account := range accountsMap {
		accountResource, err := parseAccountResource(account)
		if err != nil {
			return nil, "", annos, err
		}
		resources = append(resources, accountResource)
	}

	for _, policyGrant := range policyGrants {
		if _, ok := accountsMap[policyGrant.Subject]; !ok {
			accountResource, err := parseAccountResource(&client.Account{
				Name: policyGrant.Subject,
			})
			if err != nil {
				return nil, "", annos, err
			}
			resources = append(resources, accountResource)
			accountsMap[policyGrant.Subject] = nil
		}
	}

	return resources, "", annos, nil
}

// Entitlements always returns an empty slice for users.
func (o *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (o *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newUserBuilder creates a new userBuilder instance.
func newUserBuilder(client ArgoCdClient) *userBuilder {
	return &userBuilder{
		resourceType: userResourceType,
		client:       client,
	}
}
