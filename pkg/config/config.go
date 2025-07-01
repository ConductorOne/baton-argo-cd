package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	// Add the SchemaFields for the Config.
	UsernameField = field.StringField(
		"username",
		field.WithDescription("Username for authenticating with Argo CD CLI."),
		field.WithRequired(true),
	)
	PasswordField = field.StringField(
		"password",
		field.WithDescription("Password for authenticating with Argo CD CLI."),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	ApiUrlField = field.StringField(
		"api-url",
		field.WithDescription("API URL for Argo CD."),
		field.WithRequired(true),
	)
	ConfigurationFields = []field.SchemaField{UsernameField, PasswordField, ApiUrlField}

	// FieldRelationships defines relationships between the ConfigurationFields that can be automatically validated.
	// For example, a username and password can be required together, or an access token can be
	// marked as mutually exclusive from the username password pair.
	FieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsRequiredTogether(UsernameField, PasswordField),
	}
)

//go:generate go run -tags=generate ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("Argo Cd"),
)
