package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	UsernameField = field.StringField(
		"username",
		field.WithDescription("Username for authenticating with Argo CD CLI."),
		field.WithRequired(true),
		field.WithDisplayName("Username"),
	)
	PasswordField = field.StringField(
		"password",
		field.WithDescription("Password for authenticating with Argo CD CLI."),
		field.WithIsSecret(true),
		field.WithRequired(true),
		field.WithDisplayName("Password"),
	)
	ApiUrlField = field.StringField(
		"api-url",
		field.WithDescription("API URL for Argo CD."),
		field.WithRequired(true),
		field.WithDisplayName("API URL"),
	)
	ConfigurationFields = []field.SchemaField{UsernameField, PasswordField, ApiUrlField}

	FieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsRequiredTogether(UsernameField, PasswordField),
	}
)

var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("Argo CD"),
	field.WithHelpUrl("/docs/baton/argo-cd"),
	field.WithIconUrl("/static/app-icons/argo-cd.svg"),
)
