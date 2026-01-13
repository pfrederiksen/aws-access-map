package query

import (
	"sort"
	"strings"

	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// AccessMatrix represents a grid of principal × resource access
type AccessMatrix struct {
	Principals []string              // List of principal ARNs (rows)
	Resources  []string              // List of resource ARNs (columns)
	Grid       map[string]map[string]AccessCell // Grid[principalARN][resourceARN] = cell
	Summary    MatrixSummary
}

// AccessCell represents access for a specific principal → resource combination
type AccessCell struct {
	HasAccess       bool     // Whether principal can access resource
	AllowedActions  []string // Actions the principal can perform
	DeniedActions   []string // Actions explicitly denied
	AccessVia       string   // How access is granted (direct, group, role assumption)
	IsPublic        bool     // Whether this is public access
	IsPrivileged    bool     // Whether this grants admin-level access
}

// MatrixSummary provides aggregate statistics for the matrix
type MatrixSummary struct {
	TotalPrincipals    int
	TotalResources     int
	TotalAccessGrants  int // Number of cells with HasAccess=true
	PublicResources    int // Resources accessible by "*"
	PrivilegedAccess   int // Number of admin-level access grants
	AverageActionsPerGrant float64
}

// MatrixView determines how to organize the matrix
type MatrixView string

const (
	ViewByPrincipal MatrixView = "by-principal" // Rows = principals
	ViewByResource  MatrixView = "by-resource"  // Rows = resources
	ViewByAction    MatrixView = "by-action"    // Rows = actions
)

// GenerateAccessMatrix creates a principal × resource access matrix
func (e *Engine) GenerateAccessMatrix(actions []string) (AccessMatrix, error) {
	principals := e.graph.GetAllPrincipals()
	resources := e.graph.GetAllResources()

	// Initialize matrix
	matrix := AccessMatrix{
		Principals: make([]string, 0, len(principals)),
		Resources:  make([]string, 0, len(resources)),
		Grid:       make(map[string]map[string]AccessCell),
	}

	// Collect principal and resource ARNs
	for _, p := range principals {
		matrix.Principals = append(matrix.Principals, p.ARN)
		matrix.Grid[p.ARN] = make(map[string]AccessCell)
	}

	for _, r := range resources {
		matrix.Resources = append(matrix.Resources, r.ARN)
	}

	// Sort for consistent output
	sort.Strings(matrix.Principals)
	sort.Strings(matrix.Resources)

	// If no actions specified, use common ones
	if len(actions) == 0 {
		actions = []string{"*", "s3:*", "s3:GetObject", "iam:*", "kms:Decrypt"}
	}

	// Fill in the grid
	totalActions := 0
	for _, principalARN := range matrix.Principals {
		principal, _ := e.graph.GetPrincipal(principalARN)

		for _, resourceARN := range matrix.Resources {
			cell := AccessCell{
				AllowedActions: make([]string, 0),
				DeniedActions:  make([]string, 0),
			}

			// Check each action
			for _, action := range actions {
				if e.graph.CanAccess(principalARN, action, resourceARN, e.context) {
					cell.HasAccess = true
					cell.AllowedActions = append(cell.AllowedActions, action)

					// Check if this is privileged access
					if action == "*" || action == "iam:*" {
						cell.IsPrivileged = true
					}
				}
			}

			// Determine access method
			if len(cell.AllowedActions) > 0 {
				if principal.Type == types.PrincipalTypePublic {
					cell.AccessVia = "public"
					cell.IsPublic = true
				} else if len(principal.GroupMemberships) > 0 {
					cell.AccessVia = "group"
				} else {
					cell.AccessVia = "direct"
				}

				matrix.Summary.TotalAccessGrants++
				totalActions += len(cell.AllowedActions)

				if cell.IsPublic {
					matrix.Summary.PublicResources++
				}
				if cell.IsPrivileged {
					matrix.Summary.PrivilegedAccess++
				}
			}

			matrix.Grid[principalARN][resourceARN] = cell
		}
	}

	// Calculate summary statistics
	matrix.Summary.TotalPrincipals = len(matrix.Principals)
	matrix.Summary.TotalResources = len(matrix.Resources)

	if matrix.Summary.TotalAccessGrants > 0 {
		matrix.Summary.AverageActionsPerGrant = float64(totalActions) / float64(matrix.Summary.TotalAccessGrants)
	}

	return matrix, nil
}

// GetAccessibleResources returns all resources a principal can access
func (e *Engine) GetAccessibleResources(principalARN string, action string) ([]*types.Resource, error) {
	var accessible []*types.Resource

	for _, resource := range e.graph.GetAllResources() {
		if e.graph.CanAccess(principalARN, action, resource.ARN, e.context) {
			accessible = append(accessible, resource)
		}
	}

	return accessible, nil
}

// GetPrincipalsWithAccess returns all principals that can access a resource
func (e *Engine) GetPrincipalsWithAccess(resourceARN string, action string) ([]*types.Principal, error) {
	var principals []*types.Principal

	for _, principal := range e.graph.GetAllPrincipals() {
		if e.graph.CanAccess(principal.ARN, action, resourceARN, e.context) {
			principals = append(principals, principal)
		}
	}

	return principals, nil
}

// GeneratePrincipalAccessReport creates a detailed report for a specific principal
func (e *Engine) GeneratePrincipalAccessReport(principalARN string) (PrincipalAccessReport, error) {
	principal, ok := e.graph.GetPrincipal(principalARN)
	if !ok {
		return PrincipalAccessReport{}, nil
	}

	report := PrincipalAccessReport{
		Principal: principal,
		Resources: make(map[string]ResourceAccess),
	}

	// Common actions to check
	actions := []string{"*", "s3:*", "s3:GetObject", "s3:PutObject", "iam:*", "kms:Decrypt"}

	for _, resource := range e.graph.GetAllResources() {
		access := ResourceAccess{
			Resource:       resource,
			AllowedActions: make([]string, 0),
		}

		for _, action := range actions {
			if e.graph.CanAccess(principalARN, action, resource.ARN, e.context) {
				access.AllowedActions = append(access.AllowedActions, action)
				access.HasAccess = true
			}
		}

		if access.HasAccess {
			report.Resources[resource.ARN] = access
			report.TotalResourcesAccessible++
		}
	}

	return report, nil
}

// GenerateResourceAccessReport creates a detailed report for a specific resource
func (e *Engine) GenerateResourceAccessReport(resourceARN string) (ResourceAccessReport, error) {
	resource, ok := e.graph.GetResource(resourceARN)
	if !ok {
		return ResourceAccessReport{}, nil
	}

	report := ResourceAccessReport{
		Resource:   resource,
		Principals: make(map[string]PrincipalAccess),
	}

	// Common actions
	actions := []string{"*", "s3:*", "s3:GetObject", "s3:PutObject", "iam:*", "kms:Decrypt"}

	for _, principal := range e.graph.GetAllPrincipals() {
		access := PrincipalAccess{
			Principal:      principal,
			AllowedActions: make([]string, 0),
		}

		for _, action := range actions {
			if e.graph.CanAccess(principal.ARN, action, resourceARN, e.context) {
				access.AllowedActions = append(access.AllowedActions, action)
				access.HasAccess = true
			}
		}

		if access.HasAccess {
			if principal.Type == types.PrincipalTypePublic {
				access.IsPublic = true
				report.IsPubliclyAccessible = true
			}

			report.Principals[principal.ARN] = access
			report.TotalPrincipalsWithAccess++
		}
	}

	return report, nil
}

// PrincipalAccessReport shows all resources a principal can access
type PrincipalAccessReport struct {
	Principal               *types.Principal
	Resources               map[string]ResourceAccess
	TotalResourcesAccessible int
}

// ResourceAccess shows access details for a resource
type ResourceAccess struct {
	Resource       *types.Resource
	HasAccess      bool
	AllowedActions []string
}

// ResourceAccessReport shows all principals that can access a resource
type ResourceAccessReport struct {
	Resource                  *types.Resource
	Principals                map[string]PrincipalAccess
	TotalPrincipalsWithAccess int
	IsPubliclyAccessible      bool
}

// PrincipalAccess shows access details for a principal
type PrincipalAccess struct {
	Principal      *types.Principal
	HasAccess      bool
	AllowedActions []string
	IsPublic       bool
}

// FilterMatrix filters the access matrix based on criteria
func (m AccessMatrix) FilterMatrix(filterFunc func(cell AccessCell) bool) AccessMatrix {
	filtered := AccessMatrix{
		Principals: m.Principals,
		Resources:  m.Resources,
		Grid:       make(map[string]map[string]AccessCell),
	}

	for _, principalARN := range m.Principals {
		filtered.Grid[principalARN] = make(map[string]AccessCell)

		for _, resourceARN := range m.Resources {
			cell := m.Grid[principalARN][resourceARN]
			if filterFunc(cell) {
				filtered.Grid[principalARN][resourceARN] = cell
				if cell.HasAccess {
					filtered.Summary.TotalAccessGrants++
				}
			}
		}
	}

	filtered.Summary.TotalPrincipals = len(filtered.Principals)
	filtered.Summary.TotalResources = len(filtered.Resources)

	return filtered
}

// FilterPublicAccess returns only public access entries
func (m AccessMatrix) FilterPublicAccess() AccessMatrix {
	return m.FilterMatrix(func(cell AccessCell) bool {
		return cell.IsPublic && cell.HasAccess
	})
}

// FilterPrivilegedAccess returns only privileged access entries
func (m AccessMatrix) FilterPrivilegedAccess() AccessMatrix {
	return m.FilterMatrix(func(cell AccessCell) bool {
		return cell.IsPrivileged && cell.HasAccess
	})
}

// GetDenseRegions identifies areas of the matrix with high access density
func (m AccessMatrix) GetDenseRegions(threshold float64) []DenseRegion {
	var regions []DenseRegion

	// Calculate access density per principal
	for _, principalARN := range m.Principals {
		accessCount := 0
		for _, resourceARN := range m.Resources {
			if m.Grid[principalARN][resourceARN].HasAccess {
				accessCount++
			}
		}

		density := float64(accessCount) / float64(len(m.Resources))
		if density >= threshold {
			regions = append(regions, DenseRegion{
				PrincipalARN:  principalARN,
				ResourceCount: accessCount,
				AccessDensity: density,
				Type:          "principal",
			})
		}
	}

	// Calculate access density per resource
	for _, resourceARN := range m.Resources {
		accessCount := 0
		for _, principalARN := range m.Principals {
			if m.Grid[principalARN][resourceARN].HasAccess {
				accessCount++
			}
		}

		density := float64(accessCount) / float64(len(m.Principals))
		if density >= threshold {
			regions = append(regions, DenseRegion{
				ResourceARN:   resourceARN,
				PrincipalCount: accessCount,
				AccessDensity:  density,
				Type:           "resource",
			})
		}
	}

	// Sort by density descending
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].AccessDensity > regions[j].AccessDensity
	})

	return regions
}

// DenseRegion represents an area with high access concentration
type DenseRegion struct {
	PrincipalARN   string  // If Type="principal"
	ResourceARN    string  // If Type="resource"
	PrincipalCount int     // Number of principals (for resource regions)
	ResourceCount  int     // Number of resources (for principal regions)
	AccessDensity  float64 // Percentage of possible accesses granted
	Type           string  // "principal" or "resource"
}

// ExportToCSV formats the matrix as CSV-compatible data
func (m AccessMatrix) ExportToCSV() [][]string {
	// Header row: Principal, Resource1, Resource2, ...
	header := []string{"Principal"}
	header = append(header, m.Resources...)

	rows := [][]string{header}

	// Data rows
	for _, principalARN := range m.Principals {
		row := []string{formatARN(principalARN)}

		for _, resourceARN := range m.Resources {
			cell := m.Grid[principalARN][resourceARN]
			if cell.HasAccess {
				row = append(row, strings.Join(cell.AllowedActions, ","))
			} else {
				row = append(row, "")
			}
		}

		rows = append(rows, row)
	}

	return rows
}

// formatARN extracts the resource name from an ARN for display
func formatARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		// Return last part (resource name)
		return parts[len(parts)-1]
	}
	return arn
}
