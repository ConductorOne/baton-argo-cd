package connector

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

// parseAccountResource creates a resource for an account.
func parseAccountResource(account *client.Account) (*v2.Resource, error) {
	tokensStr := ""
	if len(account.Tokens) > 0 {
		b, err := json.Marshal(account.Tokens)
		if err == nil {
			tokensStr = string(b)
		}
	}

	profile := map[string]interface{}{
		"name":         account.Name,
		"enabled":      account.Enabled,
		"capabilities": strings.Join(account.Capabilities, client.CommaSeparator),
		"tokens":       tokensStr,
	}

	accountTraits := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
	}

	return resource.NewUserResource(
		account.Name,
		userResourceType,
		account.Name,
		accountTraits,
	)
}

// getAccountsMap fetches all accounts from ArgoCD and returns them as a map.
func getAccountsMap(ctx context.Context, c ArgoCdClient) (map[string]*client.Account, error) {
	accountsMap := make(map[string]*client.Account)
	accounts, err := c.GetAccounts(ctx)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		accCopy := account
		accountsMap[accCopy.Name] = accCopy
	}
	return accountsMap, nil
}

// getAllUserData fetches all accounts and policy grants from ArgoCD.
func getAllUserData(ctx context.Context, c ArgoCdClient) (map[string]*client.Account, []*client.PolicyGrant, annotations.Annotations, error) {
	accountsMap, err := getAccountsMap(ctx, c)
	if err != nil {
		return nil, nil, nil, err
	}

	policyGrants, annos, err := c.GetPolicyGrants(ctx)
	if err != nil {
		return nil, nil, annos, err
	}

	return accountsMap, policyGrants, annos, nil
}

// getUsersForRole returns a list of usernames that have the given role.
func getUsersForRole(ctx context.Context, c ArgoCdClient, roleName string) ([]string, annotations.Annotations, error) {
	accountsMap, policyGrants, annos, err := getAllUserData(ctx, c)
	if err != nil {
		return nil, annos, err
	}

	userToRoles := make(map[string][]string)
	for _, pg := range policyGrants {
		userToRoles[pg.Subject] = append(userToRoles[pg.Subject], pg.Role)
	}

	allUserNames := make(map[string]struct{})
	for name := range accountsMap {
		allUserNames[name] = struct{}{}
	}
	for subject := range userToRoles {
		allUserNames[subject] = struct{}{}
	}

	defaultRole, err := c.GetDefaultRole(ctx)
	if err != nil {
		return nil, annos, err
	}

	var usersWithRole []string
	for userName := range allUserNames {
		assignedRoles, hasExplicitRoles := userToRoles[userName]

		isGranted := false
		if hasExplicitRoles {
			for _, userRole := range assignedRoles {
				if userRole == roleName {
					isGranted = true
					break
				}
			}
		} else if defaultRole != "" && roleName == defaultRole {
			isGranted = true
		}

		if isGranted {
			usersWithRole = append(usersWithRole, userName)
		}
	}

	return usersWithRole, annos, nil
}
