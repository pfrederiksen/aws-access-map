package query

import (
	"fmt"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
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
// It uses BFS to discover both direct access and transitive access through role assumptions
func (e *Engine) FindPaths(fromPrincipalARN, toResourceARN, action string) ([]*types.AccessPath, error) {
	// Validate principal exists first
	principal, ok := e.graph.GetPrincipal(fromPrincipalARN)
	if !ok {
		return nil, fmt.Errorf("principal not found: %s", fromPrincipalARN)
	}

	// BFS queue: each item is (current principal, path of hops taken to get here)
	type queueItem struct {
		principalARN string
		hops         []types.AccessHop
	}

	queue := []queueItem{{principalARN: fromPrincipalARN, hops: []types.AccessHop{}}}
	visited := make(map[string]bool)
	visited[fromPrincipalARN] = true

	var paths []*types.AccessPath
	const maxDepth = 5      // Prevent runaway queries
	const maxPaths = 10     // Limit result size

	for len(queue) > 0 {
		// Check if we've found enough paths
		if len(paths) >= maxPaths {
			break
		}

		// Dequeue
		current := queue[0]
		queue = queue[1:]

		// Check depth limit
		if len(current.hops) > maxDepth {
			continue
		}

		// Check if current principal can access the target resource
		if e.graph.CanAccess(current.principalARN, action, toResourceARN) {
			resource, ok := e.graph.GetResource(toResourceARN)
			if !ok {
				// Resource doesn't exist in graph, but permission edge exists
				// This can happen with wildcard resources - skip this path
				continue
			}

			// Get the current principal for the final hop
			currentPrincipal, ok := e.graph.GetPrincipal(current.principalARN)
			if !ok {
				continue
			}

			// Build the complete path including the final permission hop
			finalHops := make([]types.AccessHop, len(current.hops))
			copy(finalHops, current.hops)

			// Add final hop: current principal → action → resource
			finalHops = append(finalHops, types.AccessHop{
				From:       currentPrincipal,
				To:         resource,
				Action:     action,
				PolicyType: types.PolicyTypeIdentity, // Could also check resource policies
			})

			path := &types.AccessPath{
				From:   principal, // Original starting principal
				To:     resource,
				Action: action,
				Hops:   finalHops,
			}
			paths = append(paths, path)

			// Don't return early - continue to explore role assumptions
			// Fall through to role expansion to find additional paths
		}

		// Expand: find roles this principal can assume
		assumableRoles := e.graph.GetRolesCanAssume(current.principalARN)
		for _, role := range assumableRoles {
			if visited[role.ARN] {
				// Skip cycles
				continue
			}

			visited[role.ARN] = true

			// Get current principal for the hop
			currentPrincipal, ok := e.graph.GetPrincipal(current.principalARN)
			if !ok {
				continue
			}

			// Build new hop: current principal → AssumeRole → role
			newHops := make([]types.AccessHop, len(current.hops))
			copy(newHops, current.hops)
			newHops = append(newHops, types.AccessHop{
				From:       currentPrincipal,
				To:         role,
				Action:     "sts:AssumeRole",
				PolicyType: types.PolicyTypeTrust,
			})

			// Enqueue the role for further exploration
			queue = append(queue, queueItem{
				principalARN: role.ARN,
				hops:         newHops,
			})
		}
	}

	return paths, nil
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
