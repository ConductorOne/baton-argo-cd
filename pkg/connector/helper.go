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

	// An unset status defaults to enabled in the SDK, which would report a disabled account as
	// active: the disable_user action leaves the account in argocd-cm with
	// accounts.<name>.enabled=false, so it keeps syncing and must carry its real state.
	resourceStatus := v2.Status_RESOURCE_STATUS_ENABLED
	if !account.Enabled {
		resourceStatus = v2.Status_RESOURCE_STATUS_DISABLED
	}

	return resource.NewUserResource(
		account.Name,
		userResourceType,
		account.Name,
		nil,
		resource.WithResourceProfile(profile),
		resource.WithResourceStatus(resourceStatus, ""),
	)
}

// generateCredentials returns the password to set: the supplied plaintext password, or a random one.
func generateCredentials(credentialOptions *v2.LocalCredentialOptions) (string, error) {
	if plaintextPassword := credentialOptions.GetPlaintextPassword(); plaintextPassword != nil {
		password := plaintextPassword.GetPlaintextPassword()
		if password == "" {
			return "", errors.New("plaintext password is empty")
		}
		return password, nil
	}

	randomPassword := credentialOptions.GetRandomPassword()
	if randomPassword == nil {
		return "", errors.New("unsupported credential option: only random or encrypted password is supported")
	}

	length := randomPassword.GetLength()
	if length < PasswordMinLength {
		length = PasswordMinLength
	}

	password, err := crypto.GenerateRandomPassword(
		&v2.LocalCredentialOptions_RandomPassword{
			Length: length,
		},
	)
	if err != nil {
		return "", err
	}
	return password, nil
}
