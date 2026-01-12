package query

import (
	"fmt"

	"github.com/yourusername/aws-access-map/internal/graph"
	"github.com/yourusername/aws-access-map/pkg/types"
)

// Engine handles queries against the access graph
type Engine struct {
	graph *graph.Graph
}

// New creates a new query engine
func New(g *graph.Graph) *Engine {
	return &Engine{graph: g}
}

// WhoCan finds all principals that can perform an action on a resource
func (e *Engine) WhoCan(resourceARN, action string) ([]*types.Principal, error) {
	var result []*types.Principal

	// Check all principals
	for _, principal := range e.graph.GetAllPrincipals() {
		// Check direct access
		if e.graph.CanAccess(principal.ARN, action, resourceARN) {
			result = append(result, principal)
		}
	}

	// TODO: Check for transitive access through role assumptions

	return result, nil
}

// FindPaths finds all access paths from a principal to a resource
func (e *Engine) FindPaths(fromPrincipalARN, toResourceARN, action string) ([]*types.AccessPath, error) {
	var paths []*types.AccessPath

	// Check direct access
	if e.graph.CanAccess(fromPrincipalARN, action, toResourceARN) {
		principal, ok := e.graph.GetPrincipal(fromPrincipalARN)
		if !ok {
			return nil, fmt.Errorf("principal not found: %s", fromPrincipalARN)
		}

		resource, ok := e.graph.GetResource(toResourceARN)
		if !ok {
			return nil, fmt.Errorf("resource not found: %s", toResourceARN)
		}

		path := &types.AccessPath{
			From:   principal,
			To:     resource,
			Action: action,
			Hops: []types.AccessHop{
				{
					From:       principal,
					To:         resource,
					Action:     action,
					PolicyType: types.PolicyTypeIdentity,
				},
			},
		}
		paths = append(paths, path)
	}

	// TODO: Find transitive paths through role assumptions using BFS

	return paths, nil
}

// FindPublicAccess identifies resources with public access
func (e *Engine) FindPublicAccess() ([]*types.Resource, error) {
	var publicResources []*types.Resource

	// TODO: Check for resources with policies allowing public access
	// Look for principals like "*" or "arn:aws:iam::*:root"

	return publicResources, nil
}

// FindHighRiskAccess identifies high-risk access patterns
func (e *Engine) FindHighRiskAccess() ([]HighRiskFinding, error) {
	var findings []HighRiskFinding

	// TODO: Implement risk detection
	// - Public access to sensitive resources
	// - Overly permissive policies (Action: "*", Resource: "*")
	// - Cross-account access
	// - Long role assumption chains

	return findings, nil
}

// HighRiskFinding represents a high-risk access pattern
type HighRiskFinding struct {
	Type        string
	Severity    string
	Description string
	Principal   *types.Principal
	Resource    *types.Resource
	Action      string
}
