package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	// Add the SchemaFields for the Config.
	AccessTokenField = field.StringField(
		"access-token",
		field.WithDescription("Access token for authenticating requests to Argo CD."),
		field.WithRequired(true),
	)
	ApiUrlField = field.StringField(
		"api-url",
		field.WithDescription("API URL for Argo CD."),
		field.WithRequired(true),
	)
	ConfigurationFields = []field.SchemaField{AccessTokenField, ApiUrlField}

	// FieldRelationships defines relationships between the ConfigurationFields that can be automatically validated.
	// For example, a username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

//go:generate go run -tags=generate ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("Argo Cd"),
)
