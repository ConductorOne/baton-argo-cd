package connector

import (
	"context"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// ArgoCdClient defines the interface for the ArgoCD client.
// It's used to abstract the client implementation for testing.
type ArgoCdClient interface {
	GetAccounts(ctx context.Context) ([]*client.Account, error)
	GetRoles(ctx context.Context) ([]*client.Role, annotations.Annotations, error)
	GetPolicyGrants(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error)
	GetDefaultRole(ctx context.Context) (string, error)
	GetSubjectsForRole(ctx context.Context, roleName string) ([]string, error)
}
