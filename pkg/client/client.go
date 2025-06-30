package client

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
)

const (
	accountsEndpoint = "/api/v1/account"
)

type Client struct {
	apiUrl      string
	accessToken string
	wrapper     *uhttp.BaseHttpClient
}

// NewClient creates a new Client instance with the provided HTTP client.
func NewClient(ctx context.Context, apiUrl string, accessToken string, httpClient *uhttp.BaseHttpClient) *Client {
	if httpClient == nil {
		httpClient = &uhttp.BaseHttpClient{}
	}
	return &Client{
		wrapper:     httpClient,
		apiUrl:      apiUrl,
		accessToken: accessToken,
	}
}

// GetAccounts fetches a paginated list of accounts from the Argo CD API.
func (c *Client) GetAccounts(ctx context.Context) ([]*Account, error) {
	accountsURL, err := buildResourceURL(c.apiUrl, accountsEndpoint)
	if err != nil {
		return nil, err
	}

	var accountsResponse AccountsResponse
	err = c.doRequest(ctx, http.MethodGet, accountsURL, &accountsResponse)
	if err != nil {
		return nil, err
	}

	var accounts []*Account
	for _, account := range accountsResponse.Items {
		accounts = append(accounts, &account)
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

	if okCsv {
		policies := strings.Split(policyData, "\n")

		for _, p := range policies {
			parts := strings.Split(strings.TrimSpace(p), CommaSeparator)
			if len(parts) < 2 {
				continue
			}

			var roleDef string
			policyType := parts[0]

			switch policyType {
			case PolicyTypeP:
				roleDef = strings.TrimSpace(parts[1])
			case PolicyTypeG:
				if len(parts) > 2 {
					roleDef = strings.TrimSpace(parts[2])
				}
			}

			if strings.HasPrefix(roleDef, RolePrefix) {
				roleName := strings.TrimPrefix(roleDef, RolePrefix)
				roleNames[roleName] = struct{}{}
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
	cm, err := getRBACConfigMap()
	if err != nil {
		return nil, nil, err
	}

	policyData, ok := cm.Data[PolicyCSVKey]
	if !ok {
		return nil, nil, nil
	}

	var grants []*PolicyGrant
	policies := strings.Split(policyData, "\n")

	for _, p := range policies {
		if !strings.HasPrefix(p, PolicyTypeG+CommaSeparator) {
			continue
		}
		parts := strings.Split(p, CommaSeparator)
		if len(parts) != 3 {
			continue
		}

		subject := strings.TrimSpace(parts[1])
		roleDef := strings.TrimSpace(parts[2])

		if strings.HasPrefix(roleDef, RolePrefix) {
			roleName := strings.TrimPrefix(roleDef, RolePrefix)
			grants = append(grants, &PolicyGrant{
				Subject: subject,
				Role:    roleName,
			})
		}
	}

	var annos annotations.Annotations
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

// doRequest executes an HTTP request and decodes the response into the provided result.
func (c *Client) doRequest(
	ctx context.Context,
	method string,
	requestURL string,
	res interface{},
) error {
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return err
	}

	requestOptions := []uhttp.RequestOption{
		uhttp.WithContentTypeJSONHeader(),
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithBearerToken(c.accessToken),
	}

	req, err := c.wrapper.NewRequest(
		ctx,
		method,
		parsedURL,
		requestOptions...,
	)
	if err != nil {
		return err
	}

	var doOptions []uhttp.DoOption
	if res != nil {
		doOptions = append(doOptions, uhttp.WithJSONResponse(res))
	}

	resp, err := c.wrapper.Do(req, doOptions...)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
