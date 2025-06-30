package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
)

const (
	PolicyDefaultKey = "policy.default"
	PolicyCSVKey     = "policy.csv"
	RolePrefix       = "role:"
	PolicyTypeP      = "p"
	PolicyTypeG      = "g"
	CommaSeparator   = ","

	// Kubectl command constants.
	Kubectl           = "kubectl"
	GetCommand        = "get"
	ConfigMapResource = "cm"
	RBACConfigMapName = "argocd-rbac-cm"
	NamespaceFlag     = "-n"
	ArgocdNamespace   = "argocd"
	OutputFlag        = "-o"
	JSONOutput        = "json"
)

// buildResourceURL builds a request URL for the Argo CD API for any endpoint and optional path elements.
func buildResourceURL(baseURL string, endpoint string) (string, error) {
	joined, err := url.JoinPath(baseURL, endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	return joined, nil
}

// getRBACConfigMap fetches and unmarshals the argocd-rbac-cm ConfigMap.
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
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run kubectl: %w, stderr: %s", err, stderr.String())
	}

	var cm ConfigMap
	err = json.Unmarshal(out.Bytes(), &cm)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configmap: %w", err)
	}

	return &cm, nil
}
