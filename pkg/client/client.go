package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
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
	var annos annotations.Annotations
	cm, err := getRBACConfigMap()
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

// GetSubjectsForRole fetches a list of subjects for a given role from the ArgoCD RBAC config map.
func (c *Client) GetSubjectsForRole(ctx context.Context, roleName string) ([]string, error) {
	cm, err := getRBACConfigMap()
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
