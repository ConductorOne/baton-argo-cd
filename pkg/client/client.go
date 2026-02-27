package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	// Policy configuration keys in RBAC ConfigMap.
	policyDefaultKey = "policy.default"
	policyCSVKey     = "policy.csv"

	// Role and policy parsing constants.
	rolePrefix = "role:"

	// PolicyTypeGrant indicates a role grant ('g') policy line.
	policyTypeGrant = "g"
	// PolicyTypeDefinition indicates a policy definition ('p') line.
	policyTypeDefinition = "p"

	// Kubernetes resource constants.
	rbacConfigMapName = "argocd-rbac-cm"
	argocdNamespace   = "argocd"

	argoCDConfigMapName        = "argocd-cm"
	defaultAccountCapabilities = "apiKey, login"
)

const (
	updateUserPasswordURL = "/api/v1/account/password" //nolint:gosec // updateUserPasswordURL is an API path, no hardcoded credentials.
	getAccountsURL        = "/api/v1/account"
	sessionURL            = "/api/v1/session"
)

// buildURL constructs a proper URL by joining the base URL with the path.
// It handles cases where the base URL might not end with a slash and the path might not start with one.
func (c *Client) buildURL(path string) (string, error) {
	baseURL, err := url.Parse(c.apiUrl)
	if err != nil {
		return "", fmt.Errorf("argocd-connector: invalid base URL: %w", err)
	}

	pathURL, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("argocd-connector: invalid path: %w", err)
	}

	return baseURL.ResolveReference(pathURL).String(), nil
}

// authRoundTripper is a custom RoundTripper that ensures authentication before each request.
type authRoundTripper struct {
	base   http.RoundTripper
	client *Client
}

// RoundTrip implements http.RoundTripper interface.
// It ensures authentication before making the request and adds auth headers.
func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Skip authentication for session endpoints to avoid infinite recursion
	reqURL := req.URL.Path
	if reqURL == sessionURL || strings.HasSuffix(reqURL, sessionURL) {
		return rt.base.RoundTrip(req)
	}

	// Ensure authentication before the request
	if err := rt.client.ensureAuthenticated(req.Context()); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to ensure authentication: %w", err)
	}

	// Add auth headers to the request
	rt.client.setAuthHeader(req)

	// Execute the request using the base transport
	return rt.base.RoundTrip(req)
}

// Client provides methods to interact with Argo CD via its REST API.
type Client struct {
	apiUrl         string
	username       string
	password       string
	kubeconfigFile []byte
	httpClient     *http.Client
	sessionToken   string
	tokenExpiry    time.Time
	k8sClient      kubernetes.Interface
}

// NewClient creates a new API Client instance.
func NewClient(ctx context.Context, apiUrl string, username string, password string,
	kubeconfigFile []byte, insecureSkipVerify bool, caCertData []byte) (*Client, error) {
	finalBaseUrl := strings.TrimSuffix(apiUrl, "/")

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if insecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if len(caCertData) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			return nil, fmt.Errorf("argocd-connector: failed to append CA certificate to cert pool")
		}
		tlsConfig.RootCAs = caCertPool
	}

	if !strings.HasPrefix(apiUrl, "http://") && !strings.HasPrefix(apiUrl, "https://") {
		finalBaseUrl = "https://" + finalBaseUrl
	}

	uhttpOpts := []uhttp.Option{
		uhttp.WithLogger(true, ctxzap.Extract(ctx)),
	}
	if insecureSkipVerify || len(caCertData) > 0 {
		uhttpOpts = append(uhttpOpts, uhttp.WithTLSClientConfig(tlsConfig))
	}
	httpClient, err := uhttp.NewClient(ctx, uhttpOpts...)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to create uhttp client: %w", err)
	}
	httpClient.Timeout = 30 * time.Second

	// Initialize Kubernetes client
	k8sClient, err := initKubernetesClient(ctx, kubeconfigFile)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to initialize Kubernetes client: %w", err)
	}

	// Create client instance first (needed for roundtripper)
	client := &Client{
		apiUrl:         finalBaseUrl,
		username:       username,
		password:       password,
		kubeconfigFile: kubeconfigFile,
		httpClient:     httpClient,
		k8sClient:      k8sClient,
	}

	// Wrap the uhttp transport with authentication roundtripper
	// This preserves uhttp's logging and other features while adding authentication
	authRT := &authRoundTripper{
		base:   httpClient.Transport,
		client: client,
	}
	httpClient.Transport = authRT

	return client, nil
}

func getUhttpClient(ctx context.Context, config *rest.Config) (*http.Client, error) {
	// Extract TLS config from Kubernetes config (includes CA certificate for in-cluster config)
	tlsConfig, err := rest.TLSConfigFor(config)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: getting TLS config from kubernetes config: %w", err)
	}

	// Build uhttp options with TLS config
	uhttpOpts := []uhttp.Option{
		uhttp.WithLogger(true, ctxzap.Extract(ctx)),
	}
	if tlsConfig != nil {
		uhttpOpts = append(uhttpOpts, uhttp.WithTLSClientConfig(tlsConfig))
	}

	// Create uhttp transport for logging with proper TLS config
	uhttpTransport, err := uhttp.NewTransport(ctx, uhttpOpts...)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: creating uhttp transport: %w", err)
	}

	// Wrap the uhttp transport with Kubernetes authentication wrappers
	// This adds Bearer token injection on top of the uhttp logging transport
	authenticatedTransport, err := rest.HTTPWrappersForConfig(config, uhttpTransport)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: wrapping transport with kubernetes authentication: %w", err)
	}

	httpClient := &http.Client{
		Transport: authenticatedTransport,
		Timeout:   300 * time.Second, // Match uhttp default timeout
	}

	return httpClient, nil
}

// initKubernetesClient initializes a Kubernetes client.
// If no kubeconfig is provided, it tries to load from ~/.kube/config or uses in-cluster config if running in a pod.
func initKubernetesClient(ctx context.Context, kubeconfigFile []byte) (kubernetes.Interface, error) {
	l := ctxzap.Extract(ctx)
	var config *rest.Config
	var err error

	// Try in-cluster config (if running inside a Kubernetes pod) if no kubeconfigFile was provided.
	if config, err = rest.InClusterConfig(); err == nil && len(kubeconfigFile) == 0 {
		// Use getUhttpClient to properly extract TLS config (including CA certificate) from rest.Config
		httpClient, err := getUhttpClient(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("argocd-connector: failed to create HTTP client for in-cluster config: %w", err)
		}
		clientset, err := kubernetes.NewForConfigAndClient(config, httpClient)
		if err != nil {
			return nil, fmt.Errorf("argocd-connector: failed to create Kubernetes clientset: %w", err)
		}
		l.Debug("Created Kubernetes clientset for in-cluster config")
		return clientset, nil
	}

	// If kubeconfig bytes are provided, load directly from bytes
	if len(kubeconfigFile) != 0 {
		config, err = clientcmd.RESTConfigFromKubeConfig(kubeconfigFile)
		if err != nil {
			return nil, fmt.Errorf("argocd-connector: failed to build Kubernetes config from provided kubeconfig: %w", err)
		}
		l.Debug("Created Kubernetes config from provided kubeconfig")
	} else {
		// Fall back to default kubeconfig file
		var kubeconfig string
		if home := homedir.HomeDir(); home != "" {
			// Default kubeconfig file
			kubeconfig = filepath.Join(home, ".kube", "config")
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("argocd-connector: failed to build Kubernetes config: %w", err)
		}
		l.Debug("Created Kubernetes config from default kubeconfig file")
	}
	httpClient, err := getUhttpClient(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to create HTTP client: %w", err)
	}
	clientset, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to create Kubernetes clientset: %w", err)
	}
	return clientset, nil
}

// ensureAuthenticated ensures the client is authenticated with ArgoCD API.
// It authenticates using the /api/v1/session endpoint and stores the session token.
// It checks token expiration and refreshes if needed (2 minutes before expiry).
func (c *Client) ensureAuthenticated(ctx context.Context) error {
	l := ctxzap.Extract(ctx)

	// If we already have a session token, check if it's still valid based on expiration
	if c.sessionToken != "" {
		// Refresh token if it expires within 2 minutes
		refreshThreshold := 2 * time.Minute
		now := time.Now()

		// If token expiry is zero (not set), we can't determine validity, so re-authenticate
		switch {
		case c.tokenExpiry.IsZero():
			l.Debug("ArgoCD API session token expiry not set, re-authenticating")
			c.sessionToken = ""
			c.tokenExpiry = time.Time{}
		case now.Add(refreshThreshold).Before(c.tokenExpiry):
			// Token is still valid (expires more than 2 minutes from now)
			l.Debug("ArgoCD API session token still valid", zap.Time("expires_at", c.tokenExpiry))
			return nil
		default:
			// Token is about to expire or has expired, clear it to force re-authentication
			l.Debug("ArgoCD API session token expired or expiring soon", zap.Time("expires_at", c.tokenExpiry), zap.Time("now", now))
			c.sessionToken = ""
			c.tokenExpiry = time.Time{}
		}
	}

	// Authenticate with ArgoCD API
	l.Debug("Authenticating with ArgoCD API")
	authURL, err := c.buildURL(sessionURL)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to build session URL: %w", err)
	}

	loginData := map[string]string{
		"username": c.username,
		"password": c.password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to marshal login data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL is constructed from admin-configured base URL and a constant path, not user input.
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to authenticate with ArgoCD API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("argocd-connector: authentication failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// If no cookie found, try to read token from response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to read response body: %w", err)
	}

	var sessionResp struct {
		Token string `json:"token"`
	}

	if err := json.Unmarshal(bodyBytes, &sessionResp); err != nil {
		return fmt.Errorf("argocd-connector: failed to parse session response: %w", err)
	}

	if sessionResp.Token == "" {
		return fmt.Errorf("argocd-connector: session token not found in response")
	}

	c.sessionToken = sessionResp.Token

	// Extract expiration from JWT token
	// ArgoCD tokens are JWTs, so we can decode them to get the expiration
	tokenExpiry, err := extractExpirationFromJWT(sessionResp.Token)
	if err != nil {
		l.Debug("Failed to extract expiration from JWT, using default 24 hours", zap.Error(err))
		// Fallback to 24 hours if we can't parse the token
		c.tokenExpiry = time.Now().Add(24 * time.Hour)
	} else {
		c.tokenExpiry = tokenExpiry
	}

	l.Debug("Successfully authenticated with ArgoCD API", zap.Time("expires_at", c.tokenExpiry))
	return nil
}

// extractExpirationFromJWT extracts the expiration time from a JWT token.
// It decodes the JWT payload and reads the 'exp' claim.
func extractExpirationFromJWT(tokenString string) (time.Time, error) {
	// Parse the JWT without verification (we only need to read the expiration)
	// JWTs are in the format: header.payload.signature
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("argocd-connector: invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("argocd-connector: failed to decode JWT payload: %w", err)
	}

	// Parse the payload JSON
	var claims struct {
		Exp *jwt.NumericDate `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("argocd-connector: failed to unmarshal JWT claims: %w", err)
	}

	if claims.Exp == nil {
		return time.Time{}, fmt.Errorf("argocd-connector: JWT does not contain 'exp' claim")
	}
	return time.Parse(time.RFC3339, string(claims.Exp.UTC().AppendFormat([]byte{}, "2006-01-02T15:04:05Z07:00")))
}

// setAuthHeader sets the authentication header for the request.
func (c *Client) setAuthHeader(req *http.Request) {
	if c.sessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.sessionToken)
	}
}

// GetAccounts fetches a list of accounts from ArgoCD using the API.
// Endpoint: GET /api/v1/account.
func (c *Client) GetAccounts(ctx context.Context) ([]*Account, error) {
	accountsURL, err := c.buildURL(getAccountsURL)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to build accounts URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, accountsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to create accounts request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL is constructed from admin-configured base URL and a constant path, not user input.
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to fetch accounts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("argocd-connector: failed to fetch accounts with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the response
	var accountsResponse struct {
		Items []*Account `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&accountsResponse); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse accounts JSON: %w", err)
	}

	return accountsResponse.Items, nil
}

// GetRBACConfigMap fetches the argocd-rbac-cm ConfigMap from the Kubernetes cluster using the K8s SDK.
func (c *Client) GetRBACConfigMap(ctx context.Context) (*corev1.ConfigMap, error) {
	l := ctxzap.Extract(ctx)

	l.Debug("attempting to fetch ConfigMap",
		zap.String("name", rbacConfigMapName),
		zap.String("namespace", argocdNamespace),
	)

	cm, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Get(ctx, rbacConfigMapName, metav1.GetOptions{})
	if err != nil {
		l.Error("failed to fetch ConfigMap",
			zap.String("name", rbacConfigMapName),
			zap.String("namespace", argocdNamespace),
			zap.Error(err),
		)
		// Log additional error details if available
		// Check if it's a Kubernetes API error
		if statusErr, ok := err.(interface {
			Status() metav1.Status
		}); ok {
			status := statusErr.Status()
			l.Error("Kubernetes API error details",
				zap.String("status", status.Status),
				zap.String("message", status.Message),
				zap.String("reason", string(status.Reason)),
				zap.Int32("code", status.Code),
			)
		}
		return nil, fmt.Errorf("argocd-connector: failed to fetch ConfigMap '%s' in namespace '%s': %w", rbacConfigMapName, argocdNamespace, err)
	}

	if cm.Data == nil {
		l.Warn("ConfigMap has no data section", zap.String("name", rbacConfigMapName))
	}

	l.Debug("Successfully fetched RBAC ConfigMap", zap.String("name", rbacConfigMapName))
	return cm, nil
}

// GetRoles fetches a list of roles from the ArgoCD RBAC config map using the Kubernetes SDK.
// It parses role definitions and grants from the 'policy.csv' key.
// It also includes the two basic built-in roles: 'readonly' and 'admin' which are not in the ConfigMap.
func (c *Client) GetRoles(ctx context.Context) ([]*Role, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var annos annotations.Annotations
	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return nil, nil, err
	}

	policyData, ok := cm.Data[policyCSVKey]
	if !ok {
		l.Warn("policy csv not found in configmap")
	}
	defaultPolicy, okDefault := cm.Data[policyDefaultKey]

	// Get role names defined in policy.csv (p, role, ...) and from grant lines (g, sub, role)
	roleNames, err := getRoleNamesFromCSV(policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("argocd-connector: failed to parse role names from policy csv: %w", err)
	}

	if okDefault && defaultPolicy != "" {
		roleName := strings.TrimPrefix(defaultPolicy, rolePrefix)
		if roleName != "" {
			roleNames[roleName] = true
		}
	}

	// Always include the two basic built-in roles that are not in the ConfigMap
	// Docs: https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#basic-built-in-roles
	roleNames["readonly"] = true
	roleNames["admin"] = true

	var roles []*Role
	for name := range roleNames {
		roles = append(roles, &Role{
			Name: name,
		})
	}

	return roles, annos, nil
}

func (c *Client) CreateAccount(ctx context.Context, username string, password string) (*Account, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	cmPatch := fmt.Sprintf(`[{"op": "add", "path": "/data/accounts.%s", "value": "%s"}]`, username, defaultAccountCapabilities)
	if _, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Patch(ctx, argoCDConfigMapName, types.JSONPatchType, []byte(cmPatch), metav1.PatchOptions{}); err != nil {
		return nil, nil, fmt.Errorf("argocd-connector: failed to update ConfigMap: %w", err)
	}
	l.Debug("ConfigMap updated successfully")
	err := c.UpdateUserPassword(ctx, username, password)
	if err != nil {
		return nil, nil, fmt.Errorf("argocd-connector: failed to update user password: %w", err)
	}
	account := &Account{
		Name:         username,
		Enabled:      true,
		Capabilities: strings.Split(defaultAccountCapabilities, ", "),
	}
	return account, nil, nil
}

func (c *Client) GetDefaultRole(ctx context.Context) (string, error) {
	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return "", err
	}

	defaultPolicy, ok := cm.Data[policyDefaultKey]
	if !ok {
		return "", nil
	}

	if defaultPolicy != "" {
		return strings.TrimPrefix(defaultPolicy, rolePrefix), nil
	}
	return "", nil
}

func (c *Client) UpdateUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[policyCSVKey]
	if !ok {
		policyCsv = ""
	}

	reader := csv.NewReader(strings.NewReader(policyCsv))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse policy csv: %w", err)
	}

	prefixedRoleID := roleID
	if !strings.HasPrefix(roleID, rolePrefix) {
		prefixedRoleID = rolePrefix + roleID
	}

	builtInRoles := map[string]bool{
		"readonly": true,
		"admin":    true,
	}
	normalizedRoleID := strings.TrimPrefix(prefixedRoleID, rolePrefix)
	isBuiltIn := builtInRoles[normalizedRoleID]

	if !isBuiltIn {
		roleExists := false
		for _, record := range records {
			if len(record) >= 2 && record[0] == policyTypeDefinition {
				recordRole := strings.TrimPrefix(record[1], rolePrefix)
				if recordRole == normalizedRoleID || record[1] == prefixedRoleID {
					roleExists = true
					break
				}
			}
		}

		if !roleExists {
			return nil, fmt.Errorf(
				"argocd-connector: role definition not found in argocd-rbac-cm ConfigMap. "+
					"Role '%s' must be defined with a policy line (p, role:%s, resource, action, object, effect) "+
					"before it can be assigned. Example: 'p, role:%s, applications, get, */*, allow'. "+
					"Add the role definition to the argocd-rbac-cm ConfigMap in the 'policy.csv' key",
				normalizedRoleID, normalizedRoleID, normalizedRoleID,
			)
		}
	}

	for _, record := range records {
		if len(record) > 2 && record[0] == policyTypeGrant && record[1] == userID && record[2] == prefixedRoleID {
			l.Debug("role already exists", zap.String("role", record[2]))
			return annotations.New(&v2.GrantAlreadyExists{}), nil
		}
	}

	l.Debug("adding role to policy", zap.String("role", prefixedRoleID))
	records = append(records, []string{policyTypeGrant, userID, prefixedRoleID})

	if err := c.updateRBACPolicy(ctx, records, ok); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to update rbac policy: %w", err)
	}

	return nil, nil
}

func (c *Client) updateRBACPolicy(ctx context.Context, records [][]string, policyExists bool) error {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.WriteAll(records); err != nil {
		return fmt.Errorf("argocd-connector: failed to write policy csv: %w", err)
	}

	updatedPolicyCsv := buf.String()

	marshaledCsv, err := json.Marshal(updatedPolicyCsv)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to marshal policy csv for patch: %w", err)
	}

	var patch string
	if policyExists {
		patch = fmt.Sprintf(`[{"op": "replace", "path": "/data/%s", "value": %s}]`, policyCSVKey, string(marshaledCsv))
	} else {
		patch = fmt.Sprintf(`[{"op": "add", "path": "/data/%s", "value": %s}]`, policyCSVKey, string(marshaledCsv))
	}

	if _, err := c.k8sClient.CoreV1().ConfigMaps(argocdNamespace).Patch(ctx, rbacConfigMapName, types.JSONPatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("argocd-connector: failed to patch rbac configmap: %w", err)
	}

	return nil
}

// UpdateUserPasswordRequest represents the request body for updating a user's password.
type UpdateUserPasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	Name            string `json:"name"`
	NewPassword     string `json:"newPassword"`
}

// UpdateUserPassword updates a user's password using the ArgoCD API.
// Endpoint: PUT /api/v1/account/password.
func (c *Client) UpdateUserPassword(ctx context.Context, username string, password string) error {
	updatePasswordURL, err := c.buildURL(updateUserPasswordURL)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to build password update URL: %w", err)
	}

	// Create the request body
	requestBody := UpdateUserPasswordRequest{
		CurrentPassword: c.password, // Use admin password as current password
		Name:            username,
		NewPassword:     password,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to marshal password update request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, updatePasswordURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to create password update request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL is constructed from admin-configured base URL and a constant path, not user input.
	if err != nil {
		return fmt.Errorf("argocd-connector: failed to update user password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("argocd-connector: failed to update user password with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Success response is empty body with 200 status
	return nil
}

// RemoveUserRole removes a role grant from a user in the `argocd-rbac-cm` ConfigMap.
// It reads the existing `policy.csv`, removes the grant, and patches the ConfigMap
// using the Kubernetes SDK.
func (c *Client) RemoveUserRole(ctx context.Context, userID string, roleID string) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[policyCSVKey]
	if !ok {
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}

	reader := csv.NewReader(strings.NewReader(policyCsv))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse policy csv: %w", err)
	}

	var newRecords [][]string
	var roleRemoved bool

	prefixedRoleID := roleID
	if !strings.HasPrefix(roleID, rolePrefix) {
		prefixedRoleID = rolePrefix + roleID
	}

	for _, record := range records {
		if len(record) > 2 && record[0] == policyTypeGrant && record[1] == userID {
			policyRole := strings.TrimPrefix(record[2], rolePrefix)
			if policyRole == roleID || record[2] == prefixedRoleID {
				roleRemoved = true
				continue
			}
		}
		newRecords = append(newRecords, record)
	}

	if !roleRemoved {
		l.Debug("role already revoked", zap.String("role", prefixedRoleID))
		return annotations.New(&v2.GrantAlreadyRevoked{}), nil
	}
	if err := c.updateRBACPolicy(ctx, newRecords, ok); err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to update rbac policy: %w", err)
	}

	return nil, nil
}

// GetRoleSubjects returns a list of subjects (users/groups) that have a given role.
// It parses the 'policy.csv' data and filters for grants matching the roleName.
func (c *Client) GetRoleSubjects(ctx context.Context, roleName string) ([]string, error) {
	cm, err := c.GetRBACConfigMap(ctx)
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to get rbac configmap: %w", err)
	}

	policyCsv, ok := cm.Data[policyCSVKey]
	if !ok {
		return nil, nil
	}

	reader := csv.NewReader(strings.NewReader(policyCsv))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("argocd-connector: failed to parse policy csv: %w", err)
	}

	var subjects []string
	prefixedRoleName := rolePrefix + roleName

	for _, record := range records {
		if len(record) == 0 {
			continue
		}

		for i := range record {
			record[i] = strings.TrimSpace(record[i])
		}

		if len(record) >= 3 && record[0] == policyTypeGrant {
			// Check if the role matches (with or without prefix)
			policyRole := strings.TrimPrefix(record[2], rolePrefix)
			if policyRole == roleName || record[2] == prefixedRoleName {
				subject := strings.TrimSpace(record[1])
				if subject != "" {
					subjects = append(subjects, subject)
				}
			}
		}
	}

	return subjects, nil
}
