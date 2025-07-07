package connector

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

const PasswordMinLength = 12

// parseAccountResource creates a resource for an account with comprehensive user traits.
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
	subjects []string,
	accountsMap map[string]bool,
) ([]*v2.Grant, error) {
	var grants []*v2.Grant

	for _, subject := range subjects {
		if accountsMap[subject] {
			grants = append(grants, createGrant(roleResource, subject))
		}
	}

	return grants, nil
}

// createGrant is a helper function to create a grant.
func createGrant(roleResource *v2.Resource, principalId string) *v2.Grant {
	userResourceID := &v2.ResourceId{
		ResourceType: userResourceType.Id,
		Resource:     principalId,
	}
	return grant.NewGrant(roleResource, assignedEntitlement, userResourceID)
}

// generateCredentials generates a random password based on the credential options.
func generateCredentials(credentialOptions *v2.CredentialOptions) (string, error) {
	if credentialOptions == nil || credentialOptions.GetRandomPassword() == nil {
		return "", errors.New("unsupported credential option: only random password is supported")
	}

	length := credentialOptions.GetRandomPassword().GetLength()
	if length < PasswordMinLength {
		length = PasswordMinLength
	}

	password, err := crypto.GenerateRandomPassword(
		&v2.CredentialOptions_RandomPassword{
			Length: length,
		},
	)
	if err != nil {
		return "", err
	}
	return password, nil
}

// handleDefaultRoleGrants assigns the default role to any user without an explicit grant.
func handleDefaultRoleGrants(
	roleResource *v2.Resource,
	accountsMap map[string]bool,
	policyGrants []*client.PolicyGrant,
) ([]*v2.Grant, error) {
	var grants []*v2.Grant
	usersWithAnyExplicitGrant := make(map[string]bool)

	for _, pg := range policyGrants {
		if accountsMap[pg.Subject] {
			usersWithAnyExplicitGrant[pg.Subject] = true
		}
	}

	for accountName := range accountsMap {
		if _, hasGrant := usersWithAnyExplicitGrant[accountName]; !hasGrant {
			grants = append(grants, createGrant(roleResource, accountName))
		}
	}

	return grants, nil
}
