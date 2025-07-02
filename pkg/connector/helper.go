package connector

import (
	"encoding/json"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

// parseAccountResource creates a resource for an account with comprehensive user traits including emails.
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
		"capabilities": strings.Join(account.Capabilities, ","),
		"tokens":       tokensStr,
	}
	emails := extractEmailsFromAccount(account)

	accountTraits := []resource.UserTraitOption{
		resource.WithUserProfile(profile),
	}

	for i, email := range emails {
		isPrimary := i == 0
		accountTraits = append(accountTraits, resource.WithEmail(email, isPrimary))
	}

	return resource.NewUserResource(
		account.Name,
		userResourceType,
		account.Name,
		accountTraits,
	)
}

// extractEmailsFromAccount attempts to extract email addresses from various sources in the account data.
func extractEmailsFromAccount(account *client.Account) []string {
	var emails []string
	emailSet := make(map[string]bool)

	emailSet[account.Name] = true

	for email := range emailSet {
		emails = append(emails, email)
	}

	return emails
}

// prepareAccountLookup creates a map for quick lookup of local account names.
func prepareAccountLookup(accounts []*client.Account) map[string]bool {
	lookup := make(map[string]bool)
	for _, acc := range accounts {
		lookup[acc.Name] = true
	}
	return lookup
}

// handleExplicitGrants processes policy grants for a specific role.
func handleExplicitGrants(
	roleResource *v2.Resource,
	policyGrants []*client.PolicyGrant,
	accountsMap map[string]bool,
	roleName string,
) ([]*v2.Grant, map[string]bool, error) {
	var grants []*v2.Grant
	usersWithRole := make(map[string]bool)

	for _, pg := range policyGrants {
		isLocalUser := accountsMap[pg.Subject]
		isForThisRole := pg.Role == roleName

		if isLocalUser && isForThisRole {
			if _, ok := usersWithRole[pg.Subject]; !ok {
				userResource, err := resource.NewUserResource(pg.Subject, userResourceType, pg.Subject, nil)
				if err != nil {
					return nil, nil, err
				}
				grants = append(grants, grant.NewGrant(roleResource, assignedEntitlement, userResource.Id))
				usersWithRole[pg.Subject] = true
			}
		}
	}

	return grants, usersWithRole, nil
}

// handleDefaultRoleGrants assigns the default role to any user without an explicit grant.
func handleDefaultRoleGrants(
	roleResource *v2.Resource,
	accounts []*client.Account,
	policyGrants []*client.PolicyGrant,
	accountsMap map[string]bool,
	usersWithExplicitRole map[string]bool,
) ([]*v2.Grant, error) {
	var grants []*v2.Grant
	usersWithAnyExplicitGrant := make(map[string]bool)

	for _, pg := range policyGrants {
		if accountsMap[pg.Subject] {
			usersWithAnyExplicitGrant[pg.Subject] = true
		}
	}

	for _, acc := range accounts {
		hasExplicitGrant := usersWithAnyExplicitGrant[acc.Name]
		alreadyHasThisRole := usersWithExplicitRole[acc.Name]
		if !hasExplicitGrant && !alreadyHasThisRole {
			userResource, err := resource.NewUserResource(acc.Name, userResourceType, acc.Name, nil)
			if err != nil {
				return nil, err
			}
			grants = append(grants, grant.NewGrant(roleResource, assignedEntitlement, userResource.Id))
		}
	}

	return grants, nil
}
