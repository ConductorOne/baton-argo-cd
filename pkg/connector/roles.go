package connector

import (
	"context"
	"fmt"
	"log"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
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
	roleName := roleResource.Id.Resource

	accounts, err := r.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get users for role: %w", err)
	}
	accountsMap := prepareAccountLookup(accounts)

	defaultRole, err := r.client.GetDefaultRole(ctx)
	if err != nil {
		log.Printf("could not fetch default role: %v", err)
	}

	var allGrants []*v2.Grant
	var annos annotations.Annotations

	if defaultRole != "" && roleName == defaultRole {
		policyGrants, policyAnnos, err := r.client.GetPolicyGrants(ctx)
		if err != nil {
			return nil, "", policyAnnos, fmt.Errorf("failed to get policy grants for default role: %w", err)
		}
		annos = policyAnnos

		defaultRoleGrants, err := handleDefaultRoleGrants(roleResource, accountsMap, policyGrants)
		if err != nil {
			return nil, "", annos, fmt.Errorf("failed to handle default role grants: %w", err)
		}
		allGrants = append(allGrants, defaultRoleGrants...)
	}

	subjects, err := r.client.GetSubjectsForRole(ctx, roleName)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to get subjects for role %s: %w", roleName, err)
	}

	explicitGrants, err := handleExplicitGrants(roleResource, subjects, accountsMap)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to handle explicit grants: %w", err)
	}
	allGrants = append(allGrants, explicitGrants...)

	return allGrants, "", annos, nil
}

// Grant assigns a role to a user. It replaces any existing roles.
func (r *roleBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	userID := principal.Id.Resource
	roleID := entitlement.Resource.Id.Resource

	policyGrants, annos, err := r.client.GetPolicyGrants(ctx)
	if err != nil {
		return nil, annos, fmt.Errorf("failed to get policy grants: %w", err)
	}

	var userRoles []string
	for _, p := range policyGrants {
		if p.Subject == userID {
			userRoles = append(userRoles, p.Role)
		}
	}

	hasRole := false
	for _, role := range userRoles {
		if role == roleID {
			hasRole = true
			break
		}
	}
	if hasRole && len(userRoles) == 1 {
		return nil, annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	annos, err = r.client.UpdateUserRole(ctx, userID, roleID)
	if err != nil {
		return nil, annos, fmt.Errorf("failed to update user role: %w", err)
	}

	grantObj := grant.NewGrant(
		entitlement.Resource,
		assignedEntitlement,
		principal.Id,
	)

	return []*v2.Grant{grantObj}, annos, nil
}

// Revoke removes a role from a user and assigns the default role.
// The connector assumes that revoking a role means reverting the user to a default role.
func (r *roleBuilder) Revoke(ctx context.Context, g *v2.Grant) (annotations.Annotations, error) {
	userID := g.Principal.Id.Resource
	roleID := g.Entitlement.Resource.Id.Resource

	defaultRole, err := r.client.GetDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get default role: %w", err)
	}

	if roleID == defaultRole {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	policyGrants, annos, err := r.client.GetPolicyGrants(ctx)
	if err != nil {
		return annos, fmt.Errorf("failed to get policy grants: %w", err)
	}

	var userRoles []string
	for _, p := range policyGrants {
		if p.Subject == userID {
			userRoles = append(userRoles, p.Role)
		}
	}

	isAlreadyDefault := false
	if len(userRoles) == 1 && userRoles[0] == defaultRole {
		isAlreadyDefault = true
	}

	if isAlreadyDefault {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	annos, err = r.client.UpdateUserRole(ctx, userID, defaultRole)
	if err != nil {
		return annos, fmt.Errorf("failed to set default role: %w", err)
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
