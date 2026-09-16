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

	// An unset status defaults to enabled in the SDK, which would report a deprovisioned
	// account as active: `disable` mode leaves the account in argocd-cm with
	// accounts.<name>.enabled=false, so it keeps syncing and must carry its real state.
	//
	// Both the resource-level status and the user trait's own status are set. The trait field
	// is deprecated in favour of the resource attribute, but NewUserTrait defaults an unset
	// trait status to enabled independently of the resource status, so setting only the
	// resource attribute would leave the two contradicting each other.
	traitStatus := v2.UserTrait_Status_STATUS_ENABLED
	resourceStatus := v2.Status_RESOURCE_STATUS_ENABLED
	if !account.Enabled {
		traitStatus = v2.UserTrait_Status_STATUS_DISABLED
		resourceStatus = v2.Status_RESOURCE_STATUS_DISABLED
	}

	accountTraits := []resource.UserTraitOption{
		//nolint:staticcheck // deprecated, but the trait status still has readers and the SDK
		// itself keeps writing it for the same backwards-compatibility reason.
		resource.WithStatus(traitStatus),
	}

	return resource.NewUserResource(
		account.Name,
		userResourceType,
		account.Name,
		accountTraits,
		resource.WithResourceProfile(profile),
		resource.WithResourceStatus(resourceStatus, ""),
	)
}

// generateCredentials generates a random password based on the credential options.
func generateCredentials(credentialOptions *v2.LocalCredentialOptions) (string, error) {
	if credentialOptions == nil || credentialOptions.GetRandomPassword() == nil {
		return "", errors.New("unsupported credential option: only random password is supported")
	}

	randomPassword := credentialOptions.GetRandomPassword()
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
