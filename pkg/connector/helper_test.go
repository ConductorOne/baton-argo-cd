package connector

import (
	"testing"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseAccountResource_Status verifies a disabled Argo CD local account syncs into C1 as
// disabled. The SDK defaults an unset status to enabled, so without an explicit status a
// `disable`-mode deprovision -- which leaves the account in argocd-cm with enabled=false and
// therefore still syncing -- would keep reporting the leaver as an active account.
func TestParseAccountResource_Status(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    v2.Status_ResourceStatus
	}{
		{name: "enabled account", enabled: true, want: v2.Status_RESOURCE_STATUS_ENABLED},
		{name: "disabled account", enabled: false, want: v2.Status_RESOURCE_STATUS_DISABLED},
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
