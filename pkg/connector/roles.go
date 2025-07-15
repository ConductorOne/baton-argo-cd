package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const assignedEntitlement = "assigned"

type roleBuilder struct {
	resourceType *v2.ResourceType
	client       ArgoCdClient
}

func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return roleResourceType
}

// List returns a list of roles.
func (r *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	roles, annos, err := r.client.GetRoles(ctx)
	if err != nil {
		return nil, "", annos, err
	}

	var resources []*v2.Resource
	for _, role := range roles {
		profile := map[string]interface{}{
			"name": role.Name,
		}
		roleResource, err := resource.NewRoleResource(
			role.Name,
			roleResourceType,
			role.Name,
			[]resource.RoleTraitOption{resource.WithRoleProfile(profile)},
		)
		if err != nil {
			return nil, "", annos, err
		}
		resources = append(resources, roleResource)
	}

	return resources, "", annos, nil
}

// Entitlements returns the entitlements for a role.
func (r *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var annos annotations.Annotations

	assigmentOptions := []entitlement.EntitlementOption{
		entitlement.WithGrantableTo(userResourceType),
		entitlement.WithDescription(fmt.Sprintf("%s to %s role", assignedEntitlement, resource.DisplayName)),
		entitlement.WithDisplayName(fmt.Sprintf("%s role %s", resource.DisplayName, assignedEntitlement)),
	}

	ent := entitlement.NewAssignmentEntitlement(
		resource,
		assignedEntitlement,
		assigmentOptions...,
	)

	return []*v2.Entitlement{ent}, "", annos, nil
}

// Grants returns the grants for a role.
func (r *roleBuilder) Grants(ctx context.Context, roleResource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	roleName := roleResource.Id.Resource

	users, err := r.client.GetRoleUsers(ctx, roleName)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get users for role %s: %w", roleName, err)
	}

	var allGrants []*v2.Grant
	var annos annotations.Annotations
	for _, user := range users {
		userResource, err := resource.NewUserResource(
			user.Name,
			userResourceType,
			user.Name,
			nil,
		)
		if err != nil {
			l.Warn("failed to create user resource",
				zap.String("user", user.Name),
				zap.Error(err),
			)
			continue
		}

		grant := grant.NewGrant(
			roleResource,
			assignedEntitlement,
			userResource.Id,
		)
		allGrants = append(allGrants, grant)
	}

	return allGrants, "", annos, nil
}

// Grant assigns a role to a user, adding it to any existing roles.
// If the user only has a default role, it will be made explicit.
func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	userID := principal.Id.Resource
	roleID := entitlement.Resource.Id.Resource

	annos, err := r.client.UpdateUserRole(ctx, userID, roleID)
	if err != nil {
		return nil, annos, fmt.Errorf("failed to update user role: %w", err)
	}

	if annos != nil {
		return nil, annos, nil
	}

	grantObj := grant.NewGrant(
		entitlement.Resource,
		assignedEntitlement,
		principal.Id,
	)

	return []*v2.Grant{grantObj}, annos, nil
}

// Revoke removes a role from a user.
func (r *roleBuilder) Revoke(ctx context.Context, g *v2.Grant) (annotations.Annotations, error) {
	userID := g.Principal.Id.Resource
	roleID := g.Entitlement.Resource.Id.Resource

	annos, err := r.client.RemoveUserRole(ctx, userID, roleID)
	if err != nil {
		return annos, fmt.Errorf("failed to remove user role: %w", err)
	}

	return annos, nil
}

// newRoleBuilder creates a new roleBuilder.
func newRoleBuilder(client ArgoCdClient) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       client,
	}
}
