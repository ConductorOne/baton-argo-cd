package test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/conductorone/baton-argo-cd/pkg/client"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

// MockClient is a mock implementation of the ArgoCD client for testing.
type MockClient struct {
	GetAccountsFunc        func(ctx context.Context) ([]*client.Account, error)
	GetRolesFunc           func(ctx context.Context) ([]*client.Role, annotations.Annotations, error)
	GetPolicyGrantsFunc    func(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error)
	GetDefaultRoleFunc     func(ctx context.Context) (string, error)
	GetSubjectsForRoleFunc func(ctx context.Context, roleName string) ([]string, error)
}

// GetAccounts calls the mock method if it is defined.
func (m *MockClient) GetAccounts(ctx context.Context) ([]*client.Account, error) {
	if m.GetAccountsFunc != nil {
		return m.GetAccountsFunc(ctx)
	}
	return nil, nil
}

// GetRoles calls the mock method if it is defined.
func (m *MockClient) GetRoles(ctx context.Context) ([]*client.Role, annotations.Annotations, error) {
	if m.GetRolesFunc != nil {
		return m.GetRolesFunc(ctx)
	}
	return nil, nil, nil
}

// GetPolicyGrants calls the mock method if it is defined.
func (m *MockClient) GetPolicyGrants(ctx context.Context) ([]*client.PolicyGrant, annotations.Annotations, error) {
	if m.GetPolicyGrantsFunc != nil {
		return m.GetPolicyGrantsFunc(ctx)
	}
	return nil, nil, nil
}

// GetDefaultRole calls the mock method if it is defined.
func (m *MockClient) GetDefaultRole(ctx context.Context) (string, error) {
	if m.GetDefaultRoleFunc != nil {
		return m.GetDefaultRoleFunc(ctx)
	}
	return "", nil
}

// GetSubjectsForRole calls the mock method if it is defined.
func (m *MockClient) GetSubjectsForRole(ctx context.Context, roleName string) ([]string, error) {
	if m.GetSubjectsForRoleFunc != nil {
		return m.GetSubjectsForRoleFunc(ctx, roleName)
	}
	return nil, nil
}

// ReadFile loads content from a JSON file from /test/mock/.
func ReadFile(fileName string) string {
	_, filename, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(filename)
	fullPath := filepath.Join(baseDir, "mock", fileName)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		panic(err)
	}
	return string(data)
}

// CreateMockResponseBody creates an io.ReadCloser with the contents of the file.
func CreateMockResponseBody(fileName string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(ReadFile(fileName)))
}

// LoadMockJSON loads the content of a mock JSON file from /test/mock/ as []byte.
func LoadMockJSON(fileName string) []byte {
	_, filename, _, _ := runtime.Caller(0)
	baseDir := filepath.Dir(filename)
	fullPath := filepath.Join(baseDir, "mock", fileName)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		panic(err)
	}
	return data
}

// LoadMockStruct loads a mock JSON file and unmarshals it into the provided interface.
func LoadMockStruct(fileName string, v interface{}) {
	data := LoadMockJSON(fileName)
	if err := json.Unmarshal(data, v); err != nil {
		panic(err)
	}
}
