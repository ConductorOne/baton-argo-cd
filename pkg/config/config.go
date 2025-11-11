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
	KubeconfigPathField = field.FileUploadField(
		"kubeconfig",
		[]string{""},
		field.WithDescription("Path to the kubeconfig file."),
		field.WithRequired(false),
		field.WithDisplayName("Kubeconfig file"),
	)
	ConfigurationFields = []field.SchemaField{
		UsernameField, PasswordField, ApiUrlField, KubeconfigPathField,
	}
	FieldRelationships = []field.SchemaFieldRelationship{
		field.FieldsRequiredTogether(UsernameField, PasswordField),
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("Argo CD"),
	field.WithHelpUrl("/docs/baton/argo-cd"),
	field.WithIconUrl("/static/app-icons/argo-cd.svg"),
)
