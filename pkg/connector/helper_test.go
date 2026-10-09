package connector

import (
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseAccountResource_Status verifies a disabled Argo CD local account syncs into C1 as
// disabled. The SDK defaults an unset status to enabled, so without an explicit status an
// account disabled by the disable_user action -- which leaves it in argocd-cm with enabled=false
// and therefore still syncing -- would keep reporting as an active account.
func TestParseAccountResource_Status(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    v2.Status_ResourceStatus
	}{
		{
			name:    "enabled account",
			enabled: true,
			want:    v2.Status_RESOURCE_STATUS_ENABLED,
		},
		{
			name:    "disabled account",
			enabled: false,
			want:    v2.Status_RESOURCE_STATUS_DISABLED,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseAccountResource(&client.Account{
				Name:         "alice",
				Enabled:      tt.enabled,
				Capabilities: []string{"login"},
			})
			require.NoError(t, err)

			assert.Equal(t, tt.want, res.GetStatus().GetStatus())

			// The profile keeps carrying the raw value for display.
			assert.Equal(t, tt.enabled, res.GetProfile().GetFields()["enabled"].GetBoolValue())
		})
	}
}

func TestGenerateCredentials(t *testing.T) {
	t.Run("supplied password is returned unchanged", func(t *testing.T) {
		password, err := generateCredentials(plaintextPasswordOptions("abc"))
		require.NoError(t, err)
		assert.Equal(t, "abc", password)
	})

	t.Run("random password is raised to the minimum length", func(t *testing.T) {
		password, err := generateCredentials(randomPasswordOptions(4))
		require.NoError(t, err)
		assert.Len(t, password, PasswordMinLength)
	})

	t.Run("random password keeps a longer requested length", func(t *testing.T) {
		password, err := generateCredentials(randomPasswordOptions(24))
		require.NoError(t, err)
		assert.Len(t, password, 24)
	})

	tests := []struct {
		name    string
		opts    *v2.LocalCredentialOptions
		wantMsg string
	}{
		{"empty supplied password", plaintextPasswordOptions(""), "plaintext password is empty"},
		{"nil options", nil, "unsupported credential option"},
		{"no password option", &v2.LocalCredentialOptions{
			Options: &v2.LocalCredentialOptions_NoPassword_{NoPassword: &v2.LocalCredentialOptions_NoPassword{}},
		}, "unsupported credential option"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateCredentials(tt.opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}
