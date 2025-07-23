package client

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// Policy configuration keys in RBAC ConfigMap.
	PolicyDefaultKey = "policy.default"
	PolicyCSVKey     = "policy.csv"

	// Role and policy parsing constants.
	RolePrefix = "role:"

	// Shell command constants.
	ShellExecutable = "sh"
	ShellFlag       = "-c"

	// PolicyTypeGrant indicates a role grant ('g') policy line.
	PolicyTypeGrant = "g"
	// PolicyTypeDefinition indicates a policy definition ('p') line.
	PolicyTypeDefinition = "p"

	// Kubectl command constants for interacting with Kubernetes.
	Kubectl           = "kubectl"
	GetCommand        = "get"
	ConfigMapResource = "cm"
	RBACConfigMapName = "argocd-rbac-cm"
	NamespaceFlag     = "-n"
	ArgocdNamespace   = "argocd"
	OutputFlag        = "-o"
	JSONOutput        = "json"

	// ArgoCD CLI command constants.
	AccountCommand     = "account"
	ListCommand        = "list"
	OutputFlagLong     = "--output"
	GetUserInfoCommand = "get-user-info"
	LoginCommand       = "login"
	LogoutCommand      = "logout"
	UsernameFlag       = "--username"
	PasswordFlag       = "--password"
	InsecureFlag       = "--insecure"
	ArgoCDCommand      = "argocd"
)

// ParseArgoCDPolicyCSV parses ArgoCD policy CSV data into group bindings and policies.
func ParseArgoCDPolicyCSV(csvData string) ([]*PolicyBinding, []*PolicyDefinition, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, nil, err
	}

	var bindings []*PolicyBinding
	var policies []*PolicyDefinition

	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		switch fields[0] {
		case PolicyTypeGrant:
			if len(fields) >= 3 {
				role := strings.TrimPrefix(fields[2], RolePrefix)
				bindings = append(bindings, &PolicyBinding{
					Subject: fields[1],
					Role:    role,
				})
			}

		case PolicyTypeDefinition:
			if len(fields) >= 4 {
				role := strings.TrimPrefix(fields[1], RolePrefix)
				policies = append(policies, &PolicyDefinition{
					Role:     role,
					Resource: fields[2],
					Action:   fields[3],
				})
			}
		default:
			continue
		}
	}

	return bindings, policies, nil
}

// executeCommand executes a command and returns an error if it fails.
func executeCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s command failed: %w, stderr: %s", name, err, stderr.String())
	}

	return nil
}

// executeCommandWithOutput executes a command and returns its stdout.
func executeCommandWithOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s command failed: %w, stderr: %s", name, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// executeShellCommandWithOutput executes a shell command string, which can include pipes.
func executeShellCommandWithOutput(ctx context.Context, command string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, ShellExecutable, ShellFlag, command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return stdout.Bytes(), nil
		}
		return nil, fmt.Errorf("shell command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// getRBACConfigMap fetches and unmarshals the argocd-rbac-cm ConfigMap from the Kubernetes cluster.
func getRBACConfigMap(ctx context.Context) (*ConfigMap, error) {
	outputBytes, err := executeCommandWithOutput(ctx, Kubectl,
		GetCommand,
		ConfigMapResource,
		RBACConfigMapName,
		NamespaceFlag,
		ArgocdNamespace,
		OutputFlag,
		JSONOutput,
	)
	if err != nil {
		return nil, fmt.Errorf("kubectl command failed to fetch ConfigMap '%s' in namespace '%s': %w",
			RBACConfigMapName, ArgocdNamespace, err)
	}

	if len(outputBytes) == 0 {
		return nil, fmt.Errorf("kubectl command returned empty output for ConfigMap '%s'", RBACConfigMapName)
	}

	var cm ConfigMap
	if err := json.Unmarshal(outputBytes, &cm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ConfigMap JSON response: %w. Raw output: %s",
			err, string(outputBytes))
	}

	if cm.Data == nil {
		return nil, fmt.Errorf("ConfigMap '%s' has no data section", RBACConfigMapName)
	}

	return &cm, nil
}

// cleanURLForCLI removes the protocol from the URL as the ArgoCD CLI doesn't accept it.
func (c *Client) cleanURLForCLI() string {
	url := c.apiUrl
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	return url
}

// ensureLoggedIn ensures the ArgoCD CLI is logged in before executing commands.
func (c *Client) ensureLoggedIn(ctx context.Context) error {
	l := ctxzap.Extract(ctx)

	if err := c.runArgoCDCommandDirect(ctx, AccountCommand, GetUserInfoCommand); err == nil {
		l.Debug("ArgoCD CLI already authenticated")
		return nil
	} else {
		l.Debug("ArgoCD CLI not authenticated or session expired", zap.Error(err))
	}

	_ = c.runArgoCDCommandDirect(ctx, LogoutCommand)

	cleanURL := c.cleanURLForCLI()

	if err := c.runArgoCDCommandDirect(ctx, LoginCommand, cleanURL,
		UsernameFlag, c.username,
		PasswordFlag, c.password,
		InsecureFlag); err != nil {
		return fmt.Errorf("argocd login failed: %w", err)
	}

	if err := c.runArgoCDCommandDirect(ctx, AccountCommand, GetUserInfoCommand); err != nil {
		return fmt.Errorf("login verification failed: %w", err)
	}

	return nil
}

// runArgoCDCommandDirect executes an ArgoCD CLI command without ensuring login first.
func (c *Client) runArgoCDCommandDirect(ctx context.Context, args ...string) error {
	return executeCommand(ctx, ArgoCDCommand, args...)
}

// runArgoCDCommandWithOutput executes an ArgoCD CLI command and returns the output.
func (c *Client) runArgoCDCommandWithOutput(ctx context.Context, args ...string) ([]byte, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure login: %w", err)
	}

	return executeCommandWithOutput(ctx, ArgoCDCommand, args...)
}

// runKubectlCommand executes a kubectl command and returns an error if it fails.
func (c *Client) runKubectlCommand(ctx context.Context, args ...string) error {
	return executeCommand(ctx, Kubectl, args...)
}

// getRoleNamesFromCSV extracts all unique role names from the policy CSV data.
func getRoleNamesFromCSV(csvData string) (map[string]struct{}, error) {
	reader := csv.NewReader(strings.NewReader(csvData))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	roleNames := make(map[string]struct{})

	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		switch fields[0] {
		case PolicyTypeGrant:
			if len(fields) >= 3 {
				role := strings.TrimPrefix(fields[2], RolePrefix)
				if role != "" {
					roleNames[role] = struct{}{}
				}
			}

		case PolicyTypeDefinition:
			if len(fields) >= 4 {
				role := strings.TrimPrefix(fields[1], RolePrefix)
				if role != "" {
					roleNames[role] = struct{}{}
				}
			}
		default:
			continue
		}
	}

	return roleNames, nil
}

// updateRBACPolicy updates the policy.csv field in the argocd-rbac-cm ConfigMap.
// It takes the full set of policy records and applies them using a kubectl patch command.
// Command: kubectl patch configmap argocd-rbac-cm --type=json -p '[{"op": "replace", ...}]'.
func (c *Client) updateRBACPolicy(ctx context.Context, records [][]string, policyExists bool) error {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.WriteAll(records); err != nil {
		return fmt.Errorf("failed to write policy csv: %w", err)
	}

	updatedPolicyCsv := buf.String()

	marshaledCsv, err := json.Marshal(updatedPolicyCsv)
	if err != nil {
		return fmt.Errorf("failed to marshal policy csv for patch: %w", err)
	}

	var patch string
	if policyExists {
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
		return fmt.Errorf("failed to patch rbac configmap: %w", err)
	}

	return nil
}

// getFilteredPolicyCSV executes a grep command on the policy.csv from the rbac configmap.
// It constructs and executes a shell command to filter the policy data.
// Command: kubectl get cm argocd-rbac-cm ... | grep ...
func getFilteredPolicyCSV(ctx context.Context, grepCmd string) ([]byte, error) {
	command := fmt.Sprintf("kubectl get cm %s -n %s -o jsonpath='{.data.policy\\.csv}' | %s",
		RBACConfigMapName,
		ArgocdNamespace,
		grepCmd,
	)

	return executeShellCommandWithOutput(ctx, command)
}
