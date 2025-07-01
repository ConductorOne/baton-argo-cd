package client

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
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

	// Kubectl command constants for interacting with Kubernetes.
	Kubectl           = "kubectl"
	GetCommand        = "get"
	ConfigMapResource = "cm"
	RBACConfigMapName = "argocd-rbac-cm"
	NamespaceFlag     = "-n"
	ArgocdNamespace   = "argocd"
	OutputFlag        = "-o"
	JSONOutput        = "json"
)

// GroupBinding represents a user/group to role binding from ArgoCD RBAC.
type GroupBinding struct {
	Subject string // user or group
	Role    string
}

// Policy represents a role-based access policy from ArgoCD RBAC.
type Policy struct {
	Role     string
	Resource string
	Action   string
	Effect   string
}

// ParseArgoCDPolicyCSV parses ArgoCD policy CSV data into group bindings and policies.
func ParseArgoCDPolicyCSV(data string) ([]GroupBinding, []Policy, error) {
	var bindings []GroupBinding
	var policies []Policy

	reader := csv.NewReader(strings.NewReader(data))
	reader.TrimLeadingSpace = true
	reader.Comment = '#'
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1

	lineNum := 0
	for {
		fields, err := reader.Read()
		lineNum++

		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			continue
		}

		if len(fields) == 0 {
			continue
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		switch fields[0] {
		case "g":
			if len(fields) >= 3 {
				role := strings.TrimPrefix(fields[2], RolePrefix)
				bindings = append(bindings, GroupBinding{
					Subject: fields[1],
					Role:    role,
				})
			}

		case "p":
			if len(fields) >= 4 {
				role := strings.TrimPrefix(fields[1], RolePrefix)
				effect := "allow"
				if len(fields) >= 5 && fields[4] != "" {
					effect = fields[4]
				}

				policies = append(policies, Policy{
					Role:     role,
					Resource: fields[2],
					Action:   fields[3],
					Effect:   effect,
				})
			}
		default:
			continue
		}
	}

	return bindings, policies, nil
}

// getRBACConfigMap fetches and unmarshals the argocd-rbac-cm ConfigMap from the Kubernetes cluster.
func getRBACConfigMap() (*ConfigMap, error) {
	cmd := exec.Command(
		Kubectl,
		GetCommand,
		ConfigMapResource,
		RBACConfigMapName,
		NamespaceFlag,
		ArgocdNamespace,
		OutputFlag,
		JSONOutput,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("kubectl command failed to fetch ConfigMap '%s' in namespace '%s': %w. stderr: %s",
			RBACConfigMapName, ArgocdNamespace, err, stderr.String())
	}

	outputBytes := stdout.Bytes()
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

	if err := c.runArgoCDCommandDirect(ctx, "account", "get-user-info"); err == nil {
		l.Debug("ArgoCD CLI already authenticated")
		return nil
	} else {
		l.Debug("ArgoCD CLI not authenticated or session expired", zap.Error(err))
	}

	_ = c.runArgoCDCommandDirect(ctx, "logout")

	cleanURL := c.cleanURLForCLI()

	if err := c.runArgoCDCommandDirect(ctx, "login", cleanURL,
		"--username", c.username,
		"--password", c.password,
		"--insecure"); err != nil {
		return fmt.Errorf("argocd login failed: %w", err)
	}

	if err := c.runArgoCDCommandDirect(ctx, "account", "get-user-info"); err != nil {
		return fmt.Errorf("login verification failed: %w", err)
	}

	return nil
}

// runArgoCDCommandDirect executes an ArgoCD CLI command without ensuring login first.
func (c *Client) runArgoCDCommandDirect(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, argoCDCommand, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("argocd command failed: %w, stderr: %s", err, stderr.String())
	}

	return nil
}

// runArgoCDCommandWithOutput executes an ArgoCD CLI command and returns the output.
func (c *Client) runArgoCDCommandWithOutput(ctx context.Context, args ...string) ([]byte, error) {
	if err := c.ensureLoggedIn(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure login: %w", err)
	}

	cmd := exec.CommandContext(ctx, argoCDCommand, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("argocd command failed: %w, stderr: %s", err, stderr.String())
	}

	return stdout.Bytes(), nil
}
