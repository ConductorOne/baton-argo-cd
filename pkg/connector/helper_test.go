package connector

import (
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseAccountResource_Status verifies a disabled Argo CD local account syncs into C1 as
// disabled. The SDK defaults an unset status to enabled, so without an explicit status an
// account disabled by the disable_user action -- which leaves it in argocd-cm with enabled=false
// and therefore still syncing -- would keep reporting as an active account.
func TestParseAccountResource_Status(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		want      v2.Status_ResourceStatus
		wantTrait v2.UserTrait_Status_Status
	}{
		{
			name:      "enabled account",
			enabled:   true,
			want:      v2.Status_RESOURCE_STATUS_ENABLED,
			wantTrait: v2.UserTrait_Status_STATUS_ENABLED,
		},
		{
			name:      "disabled account",
			enabled:   false,
			want:      v2.Status_RESOURCE_STATUS_DISABLED,
			wantTrait: v2.UserTrait_Status_STATUS_DISABLED,
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

			// The deprecated trait status must agree with the resource status: the SDK
			// defaults an unset trait status to enabled independently of the resource
			// attribute, so a disabled account would otherwise contradict itself.
			trait, err := resource.GetUserTrait(res)
			require.NoError(t, err)
			//nolint:staticcheck // asserting the deprecated trait status is the point of this test
			assert.Equal(t, tt.wantTrait, trait.GetStatus().GetStatus())

			// The profile keeps carrying the raw value for display.
			assert.Equal(t, tt.enabled, res.GetProfile().GetFields()["enabled"].GetBoolValue())
		})
	}
}
