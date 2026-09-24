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
	GetRoleSubjects(ctx context.Context, roleName string) ([]string, error)
	// Account lifecycle.
	RevokeAccountTokens(ctx context.Context, username string) error
	SetAccountEnabled(ctx context.Context, username string, enabled bool) error
	RemoveAccountRoleGrants(ctx context.Context, username string) error
	DeleteAccount(ctx context.Context, username string) error
	PurgeAccountCredentials(ctx context.Context, username string) error
	RotateAccountPassword(ctx context.Context, username string, password string) error
}
