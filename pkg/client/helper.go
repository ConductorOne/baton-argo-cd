package client

import (
	"encoding/csv"
	"fmt"
	"strings"
)

// getRoleNamesFromCSV extracts all unique role names from the policy CSV data.
// Docs: https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#rbac-model-structure
func getRoleNamesFromCSV(csvData string) (map[string]bool, error) {
	if csvData == "" {
		return make(map[string]bool), nil
	}

	reader := csv.NewReader(strings.NewReader(csvData))
	reader.Comment = '#'
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSV: %w", err)
	}

	roleNames := make(map[string]bool)
	roleNamesDefinitions := make(map[string]bool)
	rolesWithPrefix := make(map[string]bool) // Track roles with "role:" prefix

	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		switch fields[0] {
		case policyTypeGrant:
			if len(fields) >= 3 {
				role := strings.TrimPrefix(fields[2], rolePrefix)
				if role != "" {
					roleNames[role] = true
				}
			}

		case policyTypeDefinition:
			// Policy definition can be over a role (creates the role), user or group.
			if len(fields) >= 4 {
				// Check if it has the "role:" prefix before trimming
				hasRolePrefix := strings.HasPrefix(fields[1], rolePrefix)
				role := strings.TrimPrefix(fields[1], rolePrefix)
				if role != "" {
					roleNamesDefinitions[role] = true
				}
				if hasRolePrefix {
					rolesWithPrefix[role] = true
				}
			}
		default:
			continue
		}
	}

	finalRoles := make(map[string]bool)

	for role := range roleNamesDefinitions {
		// Add if it has a grant line OR if it has the "role:" prefix
		hasGrant := false
		if _, ok := roleNames[role]; ok {
			hasGrant = true
		}

		hasPrefix := false
		if _, ok := rolesWithPrefix[role]; ok {
			hasPrefix = true
		}

		if hasGrant || hasPrefix {
			// We only want to add the role to the list if it is explicitly defined in the policy.csv
			// The only way to distinguish a role in a policy definition from a user or group is if it has a grant line
			// OR if it has the "role:" prefix. Although its best practice and recommended to define the role names
			// with the prefix "role:" this is not mandatory.
			finalRoles[role] = true
		}
	}
	return finalRoles, nil
}
