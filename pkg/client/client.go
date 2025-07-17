package client

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
// It parses role definitions and grants from the 'policy.csv' key.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetRoles(ctx context.Context) ([]*Role, annotations.Annotations, error) {
	var annos annotations.Annotations
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, nil, err
	}

	policyData := cm.Data[PolicyCSVKey]
	defaultPolicy, okDefault := cm.Data[PolicyDefaultKey]

	// Get role names defined in policy.csv (p, role, ...) and from grant lines (g, sub, role)
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

// UpdateUserRole adds a role grant for a user to the `argocd-rbac-cm` ConfigMap.
// It reads the existing `policy.csv`, adds the new grant, and patches the ConfigMap
// by calling the `updateRBACPolicy` helper function.
// Command: kubectl patch configmap argocd-rbac-cm ...
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

	prefixedRoleID := roleID
	if !strings.HasPrefix(roleID, RolePrefix) {
		prefixedRoleID = RolePrefix + roleID
	}

	roleExists := false
	for _, record := range records {
		if len(record) > 2 && record[0] == userGrantPrefix && record[1] == userID && record[2] == prefixedRoleID {
			roleExists = true
			break
		}
	}

	if roleExists {
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}

	records = append(records, []string{userGrantPrefix, userID, prefixedRoleID})

	if err := c.updateRBACPolicy(ctx, records, ok); err != nil {
		return nil, fmt.Errorf("failed to update rbac policy: %w", err)
	}

	return nil, nil
}

// RemoveUserRole removes a role grant from a user in the `argocd-rbac-cm` ConfigMap.
// It reads the existing `policy.csv`, removes the grant, and patches the ConfigMap
// by calling the `updateRBACPolicy` helper function.
// Command: kubectl patch configmap argocd-rbac-cm ...
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
		if len(record) > 2 && record[0] == userGrantPrefix && record[1] == userID {
			policyRole := strings.TrimPrefix(record[2], RolePrefix)
			if policyRole == roleID {
				roleRemoved = true
				continue
			}
		}
		newRecords = append(newRecords, record)
	}

	if !roleRemoved {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	if err := c.updateRBACPolicy(ctx, newRecords, ok); err != nil {
		return nil, fmt.Errorf("failed to update rbac policy: %w", err)
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

	l := ctxzap.Extract(ctx)
	defaultRole, err := c.GetDefaultRole(ctx)
	if err != nil {
		l.Warn("failed to get default role for new user",
			zap.String("user", username),
			zap.Error(err),
		)
	}

	if defaultRole != "" {
		if _, err := c.UpdateUserRole(ctx, username, defaultRole); err != nil {
			l.Warn("failed to assign default role to new user",
				zap.String("role", defaultRole),
				zap.String("user", username),
				zap.Error(err),
			)
		}
	}

	account := &Account{
		Name:         username,
		Enabled:      true,
		Capabilities: strings.Split(defaultAccountCapabilities, ", "),
	}

	return account, nil, nil
}

// GetRoleSubjects returns a list of subjects that have a given role.
// It filters the 'policy.csv' data using a shell command.
// Command: kubectl get cm argocd-rbac-cm ... | grep -E '^g,[^,]+,ROLE_NAME$'.
func (c *Client) GetRoleSubjects(ctx context.Context, roleName string) ([]string, error) {
	// Use grep to fetch only policy lines relevant to the role.
	// It checks for the role with and without the "role:" prefix.
	grepCmd := fmt.Sprintf("grep -E '^%s,[^,]+,(%s)?%s$'", PolicyTypeGrant, RolePrefix, roleName)
	policyDataBytes, err := getFilteredPolicyCSV(ctx, grepCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command to get role subjects: %w", err)
	}

	if len(policyDataBytes) == 0 {
		return nil, nil
	}

	bindings, _, err := ParseArgoCDPolicyCSV(string(policyDataBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse filtered policy csv for role subjects: %w", err)
	}

	var subjects []string
	for _, binding := range bindings {
		subjects = append(subjects, binding.Subject)
	}

	return subjects, nil
}

// GetUserRoles returns a list of roles for a given user.
// It filters the 'policy.csv' data using a shell command.
// Command: kubectl get cm argocd-rbac-cm ... | grep -E '^g,USER_ID,'.
func (c *Client) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	// Use grep to fetch only policy lines relevant to the user.
	grepCmd := fmt.Sprintf("grep -E '^%s,%s,'", PolicyTypeGrant, userID)
	policyDataBytes, err := getFilteredPolicyCSV(ctx, grepCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command to get user roles: %w", err)
	}

	// If grep returns no results, the user has no explicit roles.
	// In this case, they may have a default role.
	if len(policyDataBytes) == 0 {
		defaultRole, err := c.GetDefaultRole(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get default role: %w", err)
		}
		if defaultRole != "" {
			return []string{defaultRole}, nil
		}
		return nil, nil
	}

	bindings, _, err := ParseArgoCDPolicyCSV(string(policyDataBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse filtered policy csv for user roles: %w", err)
	}

	var roles []string
	for _, binding := range bindings {
		roles = append(roles, binding.Role)
	}

	return roles, nil
}
