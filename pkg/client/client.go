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

// Client provides methods to interact with Argo CD CLI.
type Client struct {
	apiUrl   string
	username string
	password string
}

// NewClient creates a new Client instance.
func NewClient(ctx context.Context, apiUrl string, username string, password string) *Client {
	return &Client{
		apiUrl:   apiUrl,
		username: username,
		password: password,
	}
}

// GetAccounts fetches a list of real accounts from ArgoCD using the CLI.
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
func (c *Client) GetRoles(ctx context.Context) ([]*Role, annotations.Annotations, error) {
	cm, err := getRBACConfigMap()
	if err != nil {
		return nil, nil, err
	}

	policyData, okCsv := cm.Data[PolicyCSVKey]
	defaultPolicy, okDefault := cm.Data[PolicyDefaultKey]

	roleNames := make(map[string]struct{})

	if okDefault && defaultPolicy != "" {
		roleName := strings.TrimPrefix(defaultPolicy, RolePrefix)
		roleNames[roleName] = struct{}{}
	}

	if okCsv && strings.TrimSpace(policyData) != "" {
		bindings, policies, err := ParseArgoCDPolicyCSV(policyData)
		if err == nil {
			for _, binding := range bindings {
				if binding.Role != "" {
					roleNames[binding.Role] = struct{}{}
				}
			}
			for _, policy := range policies {
				if policy.Role != "" {
					roleNames[policy.Role] = struct{}{}
				}
			}
		}
	}

	var roles []*Role
	for name := range roleNames {
		roles = append(roles, &Role{
			Name: name,
		})
	}

	var annos annotations.Annotations
	return roles, annos, nil
}

// GetPolicyGrants fetches a list of grants from the ArgoCD RBAC config map.
func (c *Client) GetPolicyGrants(ctx context.Context) ([]*PolicyGrant, annotations.Annotations, error) {
	var annos annotations.Annotations
	cm, err := getRBACConfigMap()
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
func (c *Client) GetDefaultRole(ctx context.Context) (string, error) {
	cm, err := getRBACConfigMap()
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

// CreateAccount creates a new local user in ArgoCD with the provided username and password.
func (c *Client) CreateAccount(ctx context.Context, username string, email string, password string) (*Account, annotations.Annotations, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}
	encodedPassword := base64.StdEncoding.EncodeToString(hashedPassword)

	cmPatch := fmt.Sprintf(`[{"op": "add", "path": "/data/accounts.%s", "value": "%s"}]`, username, defaultAccountCapabilities)
	if err := c.kubectlPatch("configmap", argoCDConfigMapName, cmPatch); err != nil {
		return nil, nil, fmt.Errorf("failed to update ConfigMap: %w", err)
	}

	secretPatch := fmt.Sprintf(`[{"op": "add", "path": "/data/accounts.%s.password", "value": "%s"}]`, username, encodedPassword)
	if err := c.kubectlPatch("secret", argoCDSecretName, secretPatch); err != nil {
		return nil, nil, fmt.Errorf("failed to update Secret: %w", err)
	}

	account := &Account{
		Name:         username,
		Enabled:      true,
		Capabilities: strings.Split(defaultAccountCapabilities, ", "),
	}

	return account, nil, nil
}

// kubectlPatch is a helper method to patch Kubernetes resources.
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
