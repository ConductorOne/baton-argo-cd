package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"golang.org/x/crypto/bcrypt"
)

const (
	argoCDCommand              = "argocd"
	argoCDSecretName           = "argocd-secret"
	argoCDConfigMapName        = "argocd-cm"
	defaultAccountCapabilities = "apiKey, login"
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

// GetPolicyGrants fetches a list of grants from the ArgoCD RBAC config map.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetPolicyGrants(ctx context.Context) ([]*PolicyGrant, annotations.Annotations, error) {
	var annos annotations.Annotations
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, nil, err
	}

	policyData, ok := cm.Data[PolicyCSVKey]
	if !ok || strings.TrimSpace(policyData) == "" {
		return nil, nil, nil
	}

	var grants []*PolicyGrant

	bindings, _, err := ParseArgoCDPolicyCSV(policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse policy CSV: %w", err)
	}

	for _, binding := range bindings {
		if binding.Subject != "" && binding.Role != "" {
			grants = append(grants, &PolicyGrant{
				Subject: binding.Subject,
				Role:    binding.Role,
			})
		}
	}
	return grants, annos, nil
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
// It works by reading the existing `policy.csv`, removing all previous role assignments (`g` rules)
// for the given user, and then adding a new line for the new role assignment.
func (c *Client) UpdateUserRole(ctx context.Context, userID, roleID string) (annotations.Annotations, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[PolicyCSVKey]
	if !ok {
		policyCsv = ""
	}

	lines := strings.Split(policyCsv, "\n")
	var newLines []string

	userGrantPrefix := fmt.Sprintf("g, %s, ", userID)
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		if !strings.HasPrefix(trimmedLine, userGrantPrefix) {
			newLines = append(newLines, trimmedLine)
		}
	}

	newLines = append(newLines, fmt.Sprintf("g, %s, %s", userID, roleID))

	updatedPolicyCsv := strings.Join(newLines, "\n")

	// JSON escape the string for the patch
	marshaledCsv, err := json.Marshal(updatedPolicyCsv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy csv for patch: %w", err)
	}

	var patch string
	if ok {
		// If the key exists, replace it
		patch = fmt.Sprintf(`[{"op": "replace", "path": "/data/%s", "value": %s}]`, PolicyCSVKey, string(marshaledCsv))
	} else {
		// If the key doesn't exist, add it
		patch = fmt.Sprintf(`[{"op": "add", "path": "/data/%s", "value": %s}]`, PolicyCSVKey, string(marshaledCsv))
	}

	if err := c.kubectlPatch("configmap", RBACConfigMapName, patch); err != nil {
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

// kubectlPatch is a helper method to apply a JSON patch to a Kubernetes resource.
// It is used to modify ConfigMaps and Secrets directly.
func (c *Client) kubectlPatch(resourceType, resourceName, patch string) error {
	cmd := exec.Command(
		Kubectl,
		"patch",
		resourceType,
		resourceName,
		NamespaceFlag,
		ArgocdNamespace,
		"--type=json",
		fmt.Sprintf("-p=%s", patch),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl patch failed: %w, stderr: %s", err, stderr.String())
	}

	return nil
}

// GetSubjectsForRole fetches a list of subjects for a given role from the ArgoCD RBAC config map.
// Command: kubectl get cm argocd-rbac-cm -n argocd -o json.
func (c *Client) GetSubjectsForRole(ctx context.Context, roleName string) ([]string, error) {
	cm, err := getRBACConfigMap(ctx)
	if err != nil {
		return nil, err
	}

	policyData, ok := cm.Data[PolicyCSVKey]
	if !ok || strings.TrimSpace(policyData) == "" {
		return nil, nil
	}

	subjectMap := make(map[string]bool)

	bindings, _, err := ParseArgoCDPolicyCSV(policyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy CSV: %w", err)
	}

	for _, binding := range bindings {
		if binding.Role == roleName {
			subjectMap[binding.Subject] = true
		}
	}

	var subjects []string
	for subject := range subjectMap {
		subjects = append(subjects, subject)
	}

	return subjects, nil
}
