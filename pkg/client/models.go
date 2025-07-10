package client

// Account represents an account from the ArgoCD CLI.
type Account struct {
	Name         string         `json:"name"`
	Enabled      bool           `json:"enabled"`
	Capabilities []string       `json:"capabilities"`
	Tokens       []AccountToken `json:"tokens,omitempty"`
}

type AccountToken struct {
	ID       string `json:"id"`
	IssuedAt int64  `json:"issuedAt"`
}

// Role represents a role from the ArgoCD RBAC config map.
type Role struct {
	Name string
}

// ConfigMap is used to unmarshal the data from kubectl.
type ConfigMap struct {
	Data map[string]string `json:"data"`
}

// PolicyGrant represents a 'g' policy from the ArgoCD RBAC config map.
type PolicyGrant struct {
	Subject string
	Role    string
}

// PolicyBinding represents a user/group to role binding from ArgoCD RBAC.
type PolicyBinding struct {
	Subject string
	Role    string
}

// PolicyDefinition represents a role-based access policy from ArgoCD RBAC.
type PolicyDefinition struct {
	Role     string
	Resource string
	Action   string
	Object   string
}
