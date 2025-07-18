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
	GetDefaultRole(ctx context.Context) (string, error)
	CreateAccount(ctx context.Context, username string, password string) (*client.Account, annotations.Annotations, error)
	UpdateUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error)
	RemoveUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error)
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
	GetRoleUsers(ctx context.Context, roleID string) ([]*client.Account, error)
}
