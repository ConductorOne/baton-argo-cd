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
