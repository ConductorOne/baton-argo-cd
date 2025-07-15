package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"golang.org/x/crypto/bcrypt"
)

const (
	argoCDCommand              = "argocd"
	argoCDSecretName           = "argocd-secret"
	argoCDConfigMapName        = "argocd-cm"
	defaultAccountCapabilities = "apiKey, login"
	userGrantPrefix            = "g"
)

// Client provides methods to interact with Argo CD, primarily through its command-line interface (CLI).
// It also directly manipulates its underlying Kubernetes resources (ConfigMaps and Secrets).
// This approach is taken to manage RBAC and user accounts.
type Client struct {
	apiUrl   string
	username string
	password string
}

// NewClient creates a new Client instance.
// The credentials are used for authenticating with the Argo CD CLI.
func NewClient(ctx context.Context, apiUrl string, username string, password string) *Client {
	return &Client{
		apiUrl:   apiUrl,
		username: username,
		password: password,
	}
}

// GetAccounts fetches a list of real accounts from ArgoCD using the CLI.
// Command: argocd account list --output json.
func (c *Client) GetAccounts(ctx context.Context) ([]*Account, error) {
	output, err := c.runArgoCDCommandWithOutput(ctx, AccountCommand, ListCommand, OutputFlagLong, JSONOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	var accounts []*Account
	if err := json.Unmarshal(output, &accounts); err != nil {
		return nil, fmt.Errorf("failed to parse accounts JSON: %w (original output: %s)", err, string(output))
	}

	return accounts, nil
}

// GetRoles fetches a list of roles from the ArgoCD RBAC config map.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetRoles(ctx context.Context) ([]*Role, annotations.Annotations, error) {
	var annos annotations.Annotations
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, nil, err
	}

	policyData := cm.Data[PolicyCSVKey]
	defaultPolicy, okDefault := cm.Data[PolicyDefaultKey]

	roleNames, err := getRoleNamesFromCSV(policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse role names from policy csv: %w", err)
	}

	if okDefault && defaultPolicy != "" {
		roleName := strings.TrimPrefix(defaultPolicy, RolePrefix)
		roleNames[roleName] = struct{}{}
	}

	var roles []*Role
	for name := range roleNames {
		roles = append(roles, &Role{
			Name: name,
		})
	}
	return roles, annos, nil
}

// GetDefaultRole fetches the default role from the ArgoCD RBAC config map.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetDefaultRole(ctx context.Context) (string, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return "", err
	}

	defaultPolicy, ok := cm.Data[PolicyDefaultKey]
	if !ok {
		return "", nil
	}

	if defaultPolicy != "" {
		return strings.TrimPrefix(defaultPolicy, RolePrefix), nil
	}
	return "", nil
}

// UpdateUserRole updates the role for a user within the `argocd-rbac-cm` ConfigMap.
// It works by reading the existing `policy.csv`, checking if the user already has the role,
// and if not, adding a new line for the new role assignment.
// Command: kubectl patch configmap argocd-rbac-cm -n argocd --type=json -p '[{"op": "replace", "path": "/data/policy.csv", "value": "g, USER_ID, ROLE_ID"}]'.
func (c *Client) UpdateUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[PolicyCSVKey]
	if !ok {
		policyCsv = ""
	}

	reader := csv.NewReader(strings.NewReader(policyCsv))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy csv: %w", err)
	}

	roleExists := false
	for _, record := range records {
		if len(record) > 2 && record[0] == userGrantPrefix && record[1] == userID && record[2] == roleID {
			roleExists = true
			break
		}
	}

	if roleExists {
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	records = append(records, []string{userGrantPrefix, userID, roleID})

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.WriteAll(records); err != nil {
		return nil, fmt.Errorf("failed to write policy csv: %w", err)
	}

	updatedPolicyCsv := buf.String()

	marshaledCsv, err := json.Marshal(updatedPolicyCsv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy csv for patch: %w", err)
	}

	var patch string
	if ok {
		patch = fmt.Sprintf(`[{"op": "replace", "path": "/data/%s", "value": %s}]`, PolicyCSVKey, string(marshaledCsv))
	} else {
		patch = fmt.Sprintf(`[{"op": "add", "path": "/data/%s", "value": %s}]`, PolicyCSVKey, string(marshaledCsv))
	}

	if err := c.runKubectlCommand(
		ctx,
		"patch",
		"configmap",
		RBACConfigMapName,
		NamespaceFlag,
		ArgocdNamespace,
		"--type=json",
		fmt.Sprintf("-p=%s", patch),
	); err != nil {
		return nil, fmt.Errorf("failed to patch rbac configmap: %w", err)
	}

	return nil, nil
}

// RemoveUserRole removes a role from a user within the `argocd-rbac-cm` ConfigMap.
// Command: kubectl patch configmap argocd-rbac-cm -n argocd --type=json -p '[{"op": "replace", "path": "/data/policy.csv", "value": "g, USER_ID, ROLE_ID"}]'.
func (c *Client) RemoveUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[PolicyCSVKey]
	if !ok {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	reader := csv.NewReader(strings.NewReader(policyCsv))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy csv: %w", err)
	}

	var newRecords [][]string
	var roleRemoved bool

	for _, record := range records {
		if len(record) > 2 && record[0] == userGrantPrefix && record[1] == userID && record[2] == roleID {
			roleRemoved = true
			continue
		}
		newRecords = append(newRecords, record)
	}

	if !roleRemoved {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.WriteAll(newRecords); err != nil {
		return nil, fmt.Errorf("failed to write policy csv: %w", err)
	}

	updatedPolicyCsv := buf.String()
	marshaledCsv, err := json.Marshal(updatedPolicyCsv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy csv for patch: %w", err)
	}

	patch := fmt.Sprintf(`[{"op": "replace", "path": "/data/%s", "value": %s}]`, PolicyCSVKey, string(marshaledCsv))

	if err := c.runKubectlCommand(
		ctx,
		"patch",
		"configmap",
		RBACConfigMapName,
		NamespaceFlag,
		ArgocdNamespace,
		"--type=json",
		fmt.Sprintf("-p=%s", patch),
	); err != nil {
		return nil, fmt.Errorf("failed to patch rbac configmap: %w", err)
	}

	return nil, nil
}

// CreateAccount creates a new local user in ArgoCD with the provided username and password.
// Command: kubectl patch configmap argocd-cm -n argocd --type=json -p '[{"op": "add", "path": "/data/accounts.USERNAME", "value": "apiKey, login"}]'.
// Command: kubectl patch secret argocd-secret -n argocd --type=json -p '[{"op": "add", "path": "/data/accounts.USERNAME.password", "value": "ENCODED_PASSWORD"}]'.
func (c *Client) CreateAccount(ctx context.Context, username string, password string) (*Account, annotations.Annotations, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}
	encodedPassword := base64.StdEncoding.EncodeToString(hashedPassword)

	cmPatch := fmt.Sprintf(`[{"op": "add", "path": "/data/accounts.%s", "value": "%s"}]`, username, defaultAccountCapabilities)
	if err := c.runKubectlCommand(ctx, "patch", "configmap", argoCDConfigMapName, NamespaceFlag, ArgocdNamespace, "--type=json", "-p", cmPatch); err != nil {
		return nil, nil, fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	secretPatch := fmt.Sprintf(`[{"op": "add", "path": "/data/accounts.%s.password", "value": "%s"}]`, username, encodedPassword)
	if err := c.runKubectlCommand(ctx, "patch", "secret", argoCDSecretName, NamespaceFlag, ArgocdNamespace, "--type=json", "-p", secretPatch); err != nil {
		return nil, nil, fmt.Errorf("failed to update Secret: %w", err)
	}

	account := &Account{
		Name:         username,
		Enabled:      true,
		Capabilities: strings.Split(defaultAccountCapabilities, ", "),
	}

	return account, nil, nil
}

// GetRoleUsers returns a list of users that have the given role.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetRoleUsers(ctx context.Context, roleID string) ([]*Account, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, err
	}

	policyData, ok := cm.Data[PolicyCSVKey]
	if !ok {
		return nil, nil
	}

	reader := csv.NewReader(strings.NewReader(policyData))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy csv: %w", err)
	}

	var accounts []*Account
	for _, record := range records {
		if len(record) > 2 && record[0] == userGrantPrefix && record[2] == roleID {
			accounts = append(accounts, &Account{
				Name: record[1],
			})
		}
	}

	return accounts, nil
}

// GetUserRoles returns a list of roles for a given user.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rbac configmap: %w", err)
	}

	policyData, ok := cm.Data[PolicyCSVKey]
	if !ok {
		return nil, nil
	}

	var roles []string
	reader := csv.NewReader(strings.NewReader(policyData))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy csv: %w", err)
	}

	for _, record := range records {
		if len(record) >= 3 && record[0] == userGrantPrefix && record[1] == userID {
			role := strings.TrimPrefix(record[2], RolePrefix)
			roles = append(roles, role)
		}
	}

	defaultRole, err := c.GetDefaultRole(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get default role: %w", err)
	}

	isExplicitlyDefined := false
	for _, record := range records {
		if len(record) >= 2 && record[0] == userGrantPrefix && record[1] == userID {
			isExplicitlyDefined = true
			break
		}
	}

	if !isExplicitlyDefined && defaultRole != "" {
		roles = append(roles, defaultRole)
	}

	return roles, nil
}
