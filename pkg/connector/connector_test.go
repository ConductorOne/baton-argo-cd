package connector

import (
	"context"
	"testing"

	"github.com/conductorone/baton-argo-cd/test"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnector_Capabilities verifies the SDK discovers account deprovisioning on the user
// resource type. The SDK derives capabilities by type-asserting the resource syncers, so this
// guards the wiring rather than just the method body.
func TestConnector_Capabilities(t *testing.T) {
	ctx := context.Background()

	server, err := connectorbuilder.NewConnector(ctx, &Connector{client: &test.MockClient{}})
	require.NoError(t, err)

	md, err := server.GetMetadata(ctx, &v2.ConnectorServiceGetMetadataRequest{})
	require.NoError(t, err)

	capabilities := md.GetMetadata().GetCapabilities()
	require.NotNil(t, capabilities)

	assert.Contains(t, capabilities.GetConnectorCapabilities(), v2.Capability_CAPABILITY_RESOURCE_DELETE)

	var userCapabilities []v2.Capability
	for _, rtc := range capabilities.GetResourceTypeCapabilities() {
		if rtc.GetResourceType().GetId() == userResourceType.Id {
			userCapabilities = rtc.GetCapabilities()
		}
	}
	require.NotEmpty(t, userCapabilities, "user resource type capabilities not reported")

	assert.Contains(t, userCapabilities, v2.Capability_CAPABILITY_SYNC)
	assert.Contains(t, userCapabilities, v2.Capability_CAPABILITY_ACCOUNT_PROVISIONING)
	assert.Contains(t, userCapabilities, v2.Capability_CAPABILITY_RESOURCE_DELETE)
	// Deprovisioning must not imply resource creation: Argo CD accounts are created through the
	// account-provisioning path, not CreateResource.
	assert.NotContains(t, userCapabilities, v2.Capability_CAPABILITY_RESOURCE_CREATE)
}
