package connector

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/crypto"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
)

const PasswordMinLength = 12

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
		accountResourceType,
		account.Name,
		accountTraits,
	)
}

// extractEmailsFromAccount attempts to extract email addresses from various sources in the account data
func extractEmailsFromAccount(account *client.Account) []string {
	var emails []string
	emailSet := make(map[string]bool)

	emailSet[account.Name] = true

	for email := range emailSet {
		emails = append(emails, email)
	}

	return emails
}

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
