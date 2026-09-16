package config

import (
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateConfig tests the validation of the ArgoCD configuration.
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ArgoCd
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ArgoCd{
				Username: "admin",
				Password: "test-password",
				ApiUrl:   "https://test.com",
			},
			wantErr: false,
		},
		{
			name:    "invalid config - missing required fields",
			config:  &ArgoCd{},
			wantErr: true,
		},
		{
			name: "invalid config - missing password",
			config: &ArgoCd{
				Username: "admin",
				ApiUrl:   "https://test.com",
			},
			wantErr: true,
		},
		{
			name: "invalid config - missing username",
			config: &ArgoCd{
				Password: "test-password",
				ApiUrl:   "https://test.com",
			},
			wantErr: true,
		},
		{
			name: "valid config - disable deprovision mode",
			config: &ArgoCd{
				Username:        "admin",
				Password:        "test-password",
				ApiUrl:          "https://test.com",
				DeprovisionMode: string(client.DeprovisionModeDisable),
			},
			wantErr: false,
		},
		{
			name: "valid config - delete deprovision mode",
			config: &ArgoCd{
				Username:        "admin",
				Password:        "test-password",
				ApiUrl:          "https://test.com",
				DeprovisionMode: string(client.DeprovisionModeDelete),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := field.Validate(Config, tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestDeprovisionModeFieldDefault verifies the deprovision mode defaults to the reversible
// `disable` behaviour, so an operator who never configures the field does not get hard deletes.
func TestDeprovisionModeFieldDefault(t *testing.T) {
	assert.Equal(t, "deprovision-mode", DeprovisionModeField.FieldName)
	assert.False(t, DeprovisionModeField.Required)
	assert.Equal(t, string(client.DeprovisionModeDisable), DeprovisionModeField.DefaultValue)

	mode, err := client.ParseDeprovisionMode(DeprovisionModeField.DefaultValue.(string))
	require.NoError(t, err)
	assert.Equal(t, client.DeprovisionModeDisable, mode)
}
