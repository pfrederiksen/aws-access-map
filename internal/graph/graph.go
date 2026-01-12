package graph

import (
	"fmt"
	"sync"

	"github.com/pfrederiksen/aws-access-map/internal/policy"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// Graph represents the access graph
type Graph struct {
	mu sync.RWMutex

	// Nodes
	principals map[string]*types.Principal // ARN -> Principal
	resources  map[string]*types.Resource  // ARN -> Resource

	// Edges
	// principalActions[principalARN][action] = []resourceARN
	principalActions map[string]map[string][]string

	// trustRelations[roleARN] = []principalARN (who can assume this role)
	trustRelations map[string][]string

	// denies[principalARN][action] = []resourceARN
	denies map[string]map[string][]string
}

// New creates a new empty graph
func New() *Graph {
	return &Graph{
		principals:       make(map[string]*types.Principal),
		resources:        make(map[string]*types.Resource),
		principalActions: make(map[string]map[string][]string),
		trustRelations:   make(map[string][]string),
		denies:           make(map[string]map[string][]string),
	}
}

// Build constructs the graph from collected AWS data
func Build(collection *types.CollectionResult) (*Graph, error) {
	g := New()

	// Add all principals
	for _, principal := range collection.Principals {
		g.AddPrincipal(principal)

		// Process identity policies
		for _, policy := range principal.Policies {
			if err := g.addPolicyEdges(principal.ARN, policy); err != nil {
				return nil, fmt.Errorf("failed to process policy for %s: %w", principal.ARN, err)
			}
		}

		// Process trust policies (for roles)
		if principal.TrustPolicy != nil {
			if err := g.addTrustEdges(principal.ARN, *principal.TrustPolicy); err != nil {
				return nil, fmt.Errorf("failed to process trust policy for %s: %w", principal.ARN, err)
			}
		}
	}

	// Add all resources
	for _, resource := range collection.Resources {
		g.AddResource(resource)

		// Process resource policies
		if resource.ResourcePolicy != nil {
			if err := g.addResourcePolicyEdges(resource.ARN, *resource.ResourcePolicy); err != nil {
				return nil, fmt.Errorf("failed to process resource policy for %s: %w", resource.ARN, err)
			}
		}
	}

	return g, nil
}

// AddPrincipal adds a principal to the graph
func (g *Graph) AddPrincipal(p *types.Principal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.principals[p.ARN] = p
}

// AddResource adds a resource to the graph
func (g *Graph) AddResource(r *types.Resource) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resources[r.ARN] = r
}

// AddEdge adds a permission edge (principal can perform action on resource)
func (g *Graph) AddEdge(principalARN, action, resourceARN string, isDeny bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if isDeny {
		if g.denies[principalARN] == nil {
			g.denies[principalARN] = make(map[string][]string)
		}
		g.denies[principalARN][action] = append(g.denies[principalARN][action], resourceARN)
	} else {
		if g.principalActions[principalARN] == nil {
			g.principalActions[principalARN] = make(map[string][]string)
		}
		g.principalActions[principalARN][action] = append(g.principalActions[principalARN][action], resourceARN)
	}
}

// AddTrustRelation adds a trust relationship (trustor can assume trustee role)
func (g *Graph) AddTrustRelation(trusteeRoleARN, trustorARN string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.trustRelations[trusteeRoleARN] = append(g.trustRelations[trusteeRoleARN], trustorARN)
}

// GetPrincipal retrieves a principal by ARN
func (g *Graph) GetPrincipal(arn string) (*types.Principal, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	p, ok := g.principals[arn]
	return p, ok
}

// GetResource retrieves a resource by ARN
func (g *Graph) GetResource(arn string) (*types.Resource, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	r, ok := g.resources[arn]
	return r, ok
}

// GetAllPrincipals returns all principals in the graph
func (g *Graph) GetAllPrincipals() []*types.Principal {
	g.mu.RLock()
	defer g.mu.RUnlock()

	principals := make([]*types.Principal, 0, len(g.principals))
	for _, p := range g.principals {
		principals = append(principals, p)
	}
	return principals
}

// GetAllResources returns all resources in the graph
func (g *Graph) GetAllResources() []*types.Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	resources := make([]*types.Resource, 0, len(g.resources))
	for _, r := range g.resources {
		resources = append(resources, r)
	}
	return resources
}

// CanAccess checks if a principal can perform an action on a resource
func (g *Graph) CanAccess(principalARN, action, resourceARN string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Check for explicit deny first (deny always wins)
	// Need to check all action patterns, not just exact match
	if actionMap, ok := g.denies[principalARN]; ok {
		for actionPattern, deniedResources := range actionMap {
			// Check if the action pattern matches the queried action
			if policy.MatchesAction(actionPattern, action) {
				for _, denied := range deniedResources {
					if matchesPattern(denied, resourceARN) {
						return false
					}
				}
			}
		}
	}

	// Check for allow - also need to check action patterns
	if actionMap, ok := g.principalActions[principalARN]; ok {
		for actionPattern, allowedResources := range actionMap {
			// Check if the action pattern matches the queried action
			if policy.MatchesAction(actionPattern, action) {
				for _, allowed := range allowedResources {
					if matchesPattern(allowed, resourceARN) {
						return true
					}
				}
			}
		}
	}

	return false
}

// GetTrustedPrincipals returns all principals that can assume a role
func (g *Graph) GetTrustedPrincipals(roleARN string) []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.trustRelations[roleARN]
}

// GetRolesCanAssume returns all roles that a principal can assume
// This is the inverse of GetTrustedPrincipals - it looks up which roles
// have trust policies that allow the given principal
func (g *Graph) GetRolesCanAssume(principalARN string) []*types.Principal {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var roles []*types.Principal

	// Iterate through all trust relationships to find roles that trust this principal
	for roleARN, trustedPrincipals := range g.trustRelations {
		for _, trusted := range trustedPrincipals {
			// Check if this principal is explicitly trusted or if wildcard trust exists
			if trusted == principalARN || trusted == "*" {
				if role, ok := g.principals[roleARN]; ok {
					roles = append(roles, role)
				}
				break // Found match for this role, move to next role
			}
		}
	}

	return roles
}

// CanAssume checks if a principal can assume a specific role
func (g *Graph) CanAssume(principalARN, roleARN string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	trustedPrincipals, ok := g.trustRelations[roleARN]
	if !ok {
		return false
	}

	// Check if principal is explicitly trusted or if wildcard trust exists
	for _, trusted := range trustedPrincipals {
		if trusted == principalARN || trusted == "*" {
			return true
		}
	}

	return false
}

// addPolicyEdges processes a policy document and adds edges to the graph
func (g *Graph) addPolicyEdges(principalARN string, policy types.PolicyDocument) error {
	for _, stmt := range policy.Statements {
		actions := normalizeToSlice(stmt.Action)
		resources := normalizeToSlice(stmt.Resource)

		isDeny := stmt.Effect == types.EffectDeny

		for _, action := range actions {
			for _, resource := range resources {
				g.AddEdge(principalARN, action, resource, isDeny)
			}
		}
	}
	return nil
}

// addTrustEdges processes a trust policy and adds trust relationships
func (g *Graph) addTrustEdges(roleARN string, trustPolicy types.PolicyDocument) error {
	for _, stmt := range trustPolicy.Statements {
		if stmt.Effect != types.EffectAllow {
			continue
		}

		// Extract principals from the statement
		principals := extractPrincipals(stmt.Principal)
		for _, principal := range principals {
			g.AddTrustRelation(roleARN, principal)
		}
	}
	return nil
}

// addResourcePolicyEdges processes a resource policy and adds edges
func (g *Graph) addResourcePolicyEdges(resourceARN string, policy types.PolicyDocument) error {
	for _, stmt := range policy.Statements {
		// Extract principals allowed/denied by this resource policy
		principals := extractPrincipals(stmt.Principal)
		actions := normalizeToSlice(stmt.Action)

		isDeny := stmt.Effect == types.EffectDeny

		for _, principalARN := range principals {
			// Handle wildcard principals (public access)
			if principalARN == "*" || principalARN == "arn:aws:iam::*:root" {
				// Ensure public principal exists in graph
				if _, ok := g.GetPrincipal("*"); !ok {
					publicPrincipal := &types.Principal{
						ARN:  "*",
						Type: types.PrincipalTypePublic,
						Name: "Public (Anonymous)",
					}
					g.AddPrincipal(publicPrincipal)
				}
				principalARN = "*"
			}

			// Add edge from principal to resource for each action
			for _, action := range actions {
				g.AddEdge(principalARN, action, resourceARN, isDeny)
			}
		}
	}
	return nil
}

// normalizeToSlice converts interface{} (string or []string) to []string
func normalizeToSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	default:
		return []string{}
	}
}

// extractPrincipals extracts principal ARNs from a policy statement
func extractPrincipals(principal interface{}) []string {
	var result []string

	switch p := principal.(type) {
	case string:
		result = append(result, p)
	case map[string]interface{}:
		// Handle {"AWS": "arn:...", "Service": "lambda.amazonaws.com"}
		for _, v := range p {
			result = append(result, normalizeToSlice(v)...)
		}
	}

	return result
}

// matchesPattern checks if a resource ARN matches a pattern (with wildcards)
func matchesPattern(pattern, arn string) bool {
	return policy.MatchesResource(pattern, arn)
}
