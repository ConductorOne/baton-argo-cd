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
		entitlement.WithGrantableTo(accountResourceType),
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

	// Get real ArgoCD accounts
	accounts, err := r.client.GetAccounts(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	// Get policy grants
	policyGrants, annos, err := r.client.GetPolicyGrants(ctx)
	if err != nil {
		return nil, "", annos, fmt.Errorf("failed to get policy grants: %w", err)
	}

	// Create map of real accounts for quick lookup
	accountsMap := make(map[string]bool)
	for _, acc := range accounts {
		accountsMap[acc.Name] = true
	}

	var grants []*v2.Grant
	usersWithRole := make(map[string]bool) // Track users already granted to avoid duplicates

	// Check explicit role grants - only for real ArgoCD users
	for _, pg := range policyGrants {
		if pg.Role == roleName && accountsMap[pg.Subject] {
			if !usersWithRole[pg.Subject] {
				userResource, err := resource.NewUserResource(pg.Subject, accountResourceType, pg.Subject, nil)
				if err != nil {
					return nil, "", annos, err
				}
				grants = append(grants, grant.NewGrant(roleResource, assignedEntitlement, userResource.Id))
				usersWithRole[pg.Subject] = true
			}
		}
	}

	// Check default role - users without explicit grants get default role
	defaultRole, err := r.client.GetDefaultRole(ctx)
	if err == nil && defaultRole == roleName {
		// Find users without explicit role grants
		usersWithExplicitGrants := make(map[string]bool)
		for _, pg := range policyGrants {
			if accountsMap[pg.Subject] { // Only count real users
				usersWithExplicitGrants[pg.Subject] = true
			}
		}

		// Grant default role to users without explicit grants
		for _, acc := range accounts {
			if !usersWithExplicitGrants[acc.Name] && !usersWithRole[acc.Name] {
				userResource, err := resource.NewUserResource(acc.Name, accountResourceType, acc.Name, nil)
				if err != nil {
					return nil, "", annos, err
				}
				grants = append(grants, grant.NewGrant(roleResource, assignedEntitlement, userResource.Id))
				usersWithRole[acc.Name] = true
			}
		}
	}

	return grants, "", annos, nil
}

// newRoleBuilder creates a new roleBuilder.
func newRoleBuilder(client ArgoCdClient) *roleBuilder {
	return &roleBuilder{
		resourceType: roleResourceType,
		client:       client,
	}
}
