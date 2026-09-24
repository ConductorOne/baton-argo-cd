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
		field.WithDescription("Kubeconfig file."),
		field.WithRequired(false),
		field.WithIsSecret(true),
		field.WithDisplayName("Kubeconfig file"),
	)
	InsecureSkipVerifyField = field.BoolField(
		"insecure-skip-verify",
		field.WithDescription("Skip TLS certificate verification (insecure, use only for testing)"),
		field.WithRequired(false),
		field.WithDisplayName("Skip TLS Verification"),
		field.WithExportTarget(field.ExportTargetCLIOnly),
	)
	CACertPathField = field.FileUploadField(
		"ca-cert-path",
		[]string{""},
		field.WithDescription("Path to CA certificate file for TLS verification"),
		field.WithRequired(false),
		field.WithIsSecret(true),
		field.WithDisplayName("CA Certificate"),
	)
	ConfigurationFields = []field.SchemaField{
		UsernameField, PasswordField, ApiUrlField, KubeconfigPathField, InsecureSkipVerifyField, CACertPathField,
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
