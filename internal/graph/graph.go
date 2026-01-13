package graph

import (
	"fmt"
	"log"
	"sync"

	"github.com/pfrederiksen/aws-access-map/internal/policy"
	"github.com/pfrederiksen/aws-access-map/internal/policy/conditions"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

// PermissionEdge represents a permission edge with optional conditions
type PermissionEdge struct {
	ResourceARN string
	Conditions  map[string]map[string]interface{} // AWS condition format
	PolicyName  string                            // For debugging/display
}

// Graph represents the access graph
type Graph struct {
	mu sync.RWMutex

	// Nodes
	principals map[string]*types.Principal // ARN -> Principal
	resources  map[string]*types.Resource  // ARN -> Resource

	// Edges
	// principalActions[principalARN][action] = []PermissionEdge
	principalActions map[string]map[string][]PermissionEdge

	// trustRelations[roleARN] = []principalARN (who can assume this role)
	trustRelations map[string][]string

	// denies[principalARN][action] = []PermissionEdge
	denies map[string]map[string][]PermissionEdge

	// Organization-level constraints
	scps []types.PolicyDocument // Service Control Policies from AWS Organizations
}

// New creates a new empty graph
func New() *Graph {
	return &Graph{
		principals:       make(map[string]*types.Principal),
		resources:        make(map[string]*types.Resource),
		principalActions: make(map[string]map[string][]PermissionEdge),
		trustRelations:   make(map[string][]string),
		denies:           make(map[string]map[string][]PermissionEdge),
	}
}

// Build constructs the graph from collected AWS data
func Build(collection *types.CollectionResult) (*Graph, error) {
	g := New()

	// Store SCPs (evaluated at query time, not preprocessed into edges)
	// If SCPAttachments are available, filter SCPs for this account
	if len(collection.SCPAttachments) > 0 {
		g.scps = filterSCPsForAccount(collection.AccountID, collection.SCPAttachments, collection.OUHierarchy)
	} else {
		// Fall back to legacy SCPs field (no filtering)
		g.scps = collection.SCPs
	}

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
// For backward compatibility, this creates an edge with no conditions
func (g *Graph) AddEdge(principalARN, action, resourceARN string, isDeny bool) {
	g.AddEdgeWithConditions(principalARN, action, resourceARN, isDeny, nil, "")
}

// AddEdgeWithConditions adds a permission edge with optional conditions
func (g *Graph) AddEdgeWithConditions(principalARN, action, resourceARN string, isDeny bool, conditions map[string]map[string]interface{}, policyName string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := PermissionEdge{
		ResourceARN: resourceARN,
		Conditions:  conditions,
		PolicyName:  policyName,
	}

	if isDeny {
		if g.denies[principalARN] == nil {
			g.denies[principalARN] = make(map[string][]PermissionEdge)
		}
		g.denies[principalARN][action] = append(g.denies[principalARN][action], edge)
	} else {
		if g.principalActions[principalARN] == nil {
			g.principalActions[principalARN] = make(map[string][]PermissionEdge)
		}
		g.principalActions[principalARN][action] = append(g.principalActions[principalARN][action], edge)
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
// Optional context parameter for condition evaluation (backward compatible)
func (g *Graph) CanAccess(principalARN, action, resourceARN string, ctx ...*conditions.EvaluationContext) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Use default context if not provided (permissive behavior)
	var evalCtx *conditions.EvaluationContext
	if len(ctx) > 0 {
		evalCtx = ctx[0]
	} else {
		evalCtx = conditions.NewDefaultContext()
	}

	// STEP 0: Check SCPs (organization-level deny)
	// SCPs are checked FIRST before any other policies
	if g.isBlockedBySCP(principalARN, action, resourceARN, evalCtx) {
		return false // SCP denies this action organization-wide
	}

	// STEP 1: Check permission boundaries (principal-level filter)
	// Boundaries act as permission filters - action must be explicitly allowed
	if g.isBlockedByBoundary(principalARN, action, resourceARN, evalCtx) {
		return false // Permission boundary blocks this action
	}

	// STEP 2: Check session policies (temporary session constraints)
	// Session policies narrow permissions during assumed role sessions
	if g.isBlockedBySessionPolicy(action, resourceARN, evalCtx) {
		return false // Session policy blocks this action
	}

	// STEP 3: Check for explicit deny from identity/resource policies (deny always wins)
	// Need to check all action patterns, not just exact match
	if actionMap, ok := g.denies[principalARN]; ok {
		for actionPattern, denyEdges := range actionMap {
			// Check if the action pattern matches the queried action
			if policy.MatchesAction(actionPattern, action) {
				for _, edge := range denyEdges {
					if matchesPattern(edge.ResourceARN, resourceARN) {
						// Evaluate conditions
						matched, err := conditions.Evaluate(edge.Conditions, evalCtx)
						if err != nil {
							// For deny rules, fail closed (conservative) - if we can't
							// evaluate the condition, assume the deny applies for safety
							log.Printf("Warning: Failed to evaluate deny condition for %s on %s: %v (assuming deny applies)",
								principalARN, resourceARN, err)
							return false
						}
						if matched {
							// Deny condition matched - explicit deny wins
							return false
						}
					}
				}
			}
		}
	}

	// STEP 3.5: Check for explicit deny from group policies (deny always wins)
	// Users inherit deny rules from their groups
	if principal, exists := g.principals[principalARN]; exists {
		if len(principal.GroupMemberships) > 0 {
			for _, groupARN := range principal.GroupMemberships {
				// Check if this group has any deny rules
				if actionMap, ok := g.denies[groupARN]; ok {
					for actionPattern, denyEdges := range actionMap {
						if policy.MatchesAction(actionPattern, action) {
							for _, edge := range denyEdges {
								if matchesPattern(edge.ResourceARN, resourceARN) {
									// Evaluate conditions
									matched, err := conditions.Evaluate(edge.Conditions, evalCtx)
									if err != nil {
										log.Printf("Warning: Failed to evaluate deny condition for group %s on %s: %v (assuming deny applies)",
											groupARN, resourceARN, err)
										return false
									}
									if matched {
										// Deny from group - explicit deny wins
										return false
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// STEP 4: Check for explicit allow from identity policies
	// Check for allow - also need to check action patterns
	if actionMap, ok := g.principalActions[principalARN]; ok {
		for actionPattern, allowEdges := range actionMap {
			// Check if the action pattern matches the queried action
			if policy.MatchesAction(actionPattern, action) {
				for _, edge := range allowEdges {
					if matchesPattern(edge.ResourceARN, resourceARN) {
						// Evaluate conditions
						matched, err := conditions.Evaluate(edge.Conditions, evalCtx)
						if err != nil {
							// For allow rules, skip this edge if condition can't be evaluated
							// (this particular allow doesn't apply, but others might)
							log.Printf("Warning: Failed to evaluate allow condition for %s on %s: %v (skipping this allow)",
								principalARN, resourceARN, err)
							continue
						}
						if matched {
							// Allow condition matched
							return true
						}
					}
				}
			}
		}
	}

	// STEP 4.5: Check group memberships (users inherit group permissions)
	// If the principal is a user, check if any of their groups grant access
	if principal, exists := g.principals[principalARN]; exists {
		if len(principal.GroupMemberships) > 0 {
			for _, groupARN := range principal.GroupMemberships {
				// Recursively check if the group has access
				// Pass the evaluation context through to maintain condition checks
				if g.CanAccess(groupARN, action, resourceARN, evalCtx) {
					return true // User inherits permission from group
				}
			}
		}
	}

	// STEP 5: Default deny (implicit)
	// No explicit allow found, so access is implicitly denied
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
				// Preserve conditions from the statement
				g.AddEdgeWithConditions(principalARN, action, resource, isDeny, stmt.Condition, stmt.Sid)
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
			// Preserve conditions from resource policy
			for _, action := range actions {
				g.AddEdgeWithConditions(principalARN, action, resourceARN, isDeny, stmt.Condition, stmt.Sid)
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

// isBlockedBySCP checks if a Service Control Policy blocks the action
// SCPs act as permission boundaries (allowlists):
// 1. Actions must be explicitly allowed by at least one SCP
// 2. If no SCP allows an action, it is implicitly denied
// 3. Explicit denies override any allows
func (g *Graph) isBlockedBySCP(principalARN, action, resourceARN string, ctx *conditions.EvaluationContext) bool {
	// Root user is not affected by SCPs (AWS special case)
	if isRootUser(principalARN) {
		return false
	}

	// If no SCPs exist, nothing is blocked (from SCP perspective)
	if len(g.scps) == 0 {
		return false
	}

	// Step 1: Check if action is explicitly allowed by at least one SCP
	hasExplicitAllow := false
	for _, scp := range g.scps {
		for _, stmt := range scp.Statements {
			if stmt.Effect != types.EffectAllow {
				continue
			}

			// Check if this SCP allow applies to the action
			actions := normalizeToSlice(stmt.Action)
			resources := normalizeToSlice(stmt.Resource)

			// Check if action matches
			actionMatches := false
			for _, scpAction := range actions {
				if policy.MatchesAction(scpAction, action) {
					actionMatches = true
					break
				}
			}

			if !actionMatches {
				continue
			}

			// Check if resource matches
			resourceMatches := false
			for _, scpResource := range resources {
				if matchesPattern(scpResource, resourceARN) {
					resourceMatches = true
					break
				}
			}

			if !resourceMatches {
				continue
			}

			// Check conditions if present
			if len(stmt.Condition) > 0 {
				matched, err := conditions.Evaluate(stmt.Condition, ctx)
				if err != nil {
					// Fail closed for allow conditions - if we can't evaluate, skip this allow
					log.Printf("Warning: Failed to evaluate SCP allow condition (policy %s): %v (skipping this allow)", scp.ID, err)
					continue
				}
				if !matched {
					// Conditions didn't match, allow doesn't apply
					continue
				}
			}

			// Found an explicit allow
			hasExplicitAllow = true
			break
		}

		if hasExplicitAllow {
			break
		}
	}

	// Step 2: If no explicit allow found, action is implicitly denied
	if !hasExplicitAllow {
		return true
	}

	// Step 3: Check for explicit deny (deny overrides allow)
	for _, scp := range g.scps {
		for _, stmt := range scp.Statements {
			if stmt.Effect != types.EffectDeny {
				continue
			}

			// Check if this SCP deny applies to the action
			actions := normalizeToSlice(stmt.Action)
			resources := normalizeToSlice(stmt.Resource)

			// Check if action matches
			actionMatches := false
			for _, scpAction := range actions {
				if policy.MatchesAction(scpAction, action) {
					actionMatches = true
					break
				}
			}

			if !actionMatches {
				continue
			}

			// Check if resource matches
			resourceMatches := false
			for _, scpResource := range resources {
				if matchesPattern(scpResource, resourceARN) {
					resourceMatches = true
					break
				}
			}

			if !resourceMatches {
				continue
			}

			// Check conditions if present
			if len(stmt.Condition) > 0 {
				matched, err := conditions.Evaluate(stmt.Condition, ctx)
				if err != nil {
					// Fail closed for SCP deny conditions (security-first)
					log.Printf("Warning: Failed to evaluate SCP deny condition (policy %s): %v (assuming deny applies)", scp.ID, err)
					return true
				}
				if !matched {
					// Conditions didn't match, deny doesn't apply
					continue
				}
			}

			// SCP explicitly denies this action
			return true
		}
	}

	// Has explicit allow and no explicit deny
	return false
}

// isBlockedByBoundary checks if a permission boundary blocks the action
// Permission boundaries act as permission filters (allowlists):
// 1. Actions must be explicitly allowed by the boundary
// 2. If no boundary exists, nothing is blocked
// 3. If boundary exists but doesn't allow action, it's implicitly denied
// 4. Explicit denies in boundaries also block
func (g *Graph) isBlockedByBoundary(principalARN, action, resourceARN string, ctx *conditions.EvaluationContext) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Look up the principal to get their boundary
	principal, exists := g.principals[principalARN]
	if !exists {
		// Principal not found - no boundary to check
		return false
	}

	// If no permission boundary attached, nothing is blocked
	if principal.PermissionsBoundary == nil {
		return false
	}

	boundary := principal.PermissionsBoundary

	// Step 1: Check if action is explicitly allowed by the boundary
	hasExplicitAllow := false
	for _, stmt := range boundary.Statements {
		if stmt.Effect != types.EffectAllow {
			continue
		}

		// Check if this boundary allow applies to the action
		actions := normalizeToSlice(stmt.Action)
		resources := normalizeToSlice(stmt.Resource)

		// Check if action matches
		actionMatches := false
		for _, boundaryAction := range actions {
			if policy.MatchesAction(boundaryAction, action) {
				actionMatches = true
				break
			}
		}

		if !actionMatches {
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, boundaryResource := range resources {
			if matchesPattern(boundaryResource, resourceARN) {
				resourceMatches = true
				break
			}
		}

		if !resourceMatches {
			continue
		}

		// Check conditions if present
		if len(stmt.Condition) > 0 {
			matched, err := conditions.Evaluate(stmt.Condition, ctx)
			if err != nil {
				// Fail closed for allow conditions - if we can't evaluate, skip this allow
				log.Printf("Warning: Failed to evaluate boundary allow condition (policy %s): %v (skipping this allow)", boundary.ID, err)
				continue
			}
			if !matched {
				// Conditions didn't match, allow doesn't apply
				continue
			}
		}

		// Found an explicit allow
		hasExplicitAllow = true
		break
	}

	// Step 2: If no explicit allow found, action is implicitly denied by boundary
	if !hasExplicitAllow {
		return true
	}

	// Step 3: Check for explicit deny (deny overrides allow)
	for _, stmt := range boundary.Statements {
		if stmt.Effect != types.EffectDeny {
			continue
		}

		actions := normalizeToSlice(stmt.Action)
		resources := normalizeToSlice(stmt.Resource)

		// Check if action matches
		actionMatches := false
		for _, boundaryAction := range actions {
			if policy.MatchesAction(boundaryAction, action) {
				actionMatches = true
				break
			}
		}

		if !actionMatches {
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, boundaryResource := range resources {
			if matchesPattern(boundaryResource, resourceARN) {
				resourceMatches = true
				break
			}
		}

		if !resourceMatches {
			continue
		}

		// Check conditions if present
		if len(stmt.Condition) > 0 {
			matched, err := conditions.Evaluate(stmt.Condition, ctx)
			if err != nil {
				// Fail closed for deny conditions - if we can't evaluate, treat as deny
				log.Printf("Warning: Failed to evaluate boundary deny condition (policy %s): %v (treating as deny)", boundary.ID, err)
				return true
			}
			if !matched {
				// Conditions didn't match, deny doesn't apply
				continue
			}
		}

		// Explicit deny found
		return true
	}

	// Has explicit allow and no explicit deny
	return false
}

// isBlockedBySessionPolicy checks if a session policy blocks the action
// Session policies are temporary constraints applied during role assumption
// They narrow permissions (allowlist) and cannot grant additional access
func (g *Graph) isBlockedBySessionPolicy(action, resourceARN string, ctx *conditions.EvaluationContext) bool {
	// If no session policy in context, nothing is blocked
	if ctx == nil || ctx.SessionPolicy == nil {
		return false
	}

	sessionPolicy := ctx.SessionPolicy

	// Step 1: Check if action is explicitly allowed by the session policy
	hasExplicitAllow := false
	for _, stmt := range sessionPolicy.Statements {
		if stmt.Effect != types.EffectAllow {
			continue
		}

		// Check if this session policy allow applies to the action
		actions := normalizeToSlice(stmt.Action)
		resources := normalizeToSlice(stmt.Resource)

		// Check if action matches
		actionMatches := false
		for _, sessionAction := range actions {
			if policy.MatchesAction(sessionAction, action) {
				actionMatches = true
				break
			}
		}

		if !actionMatches {
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, sessionResource := range resources {
			if matchesPattern(sessionResource, resourceARN) {
				resourceMatches = true
				break
			}
		}

		if !resourceMatches {
			continue
		}

		// Check conditions if present
		if len(stmt.Condition) > 0 {
			matched, err := conditions.Evaluate(stmt.Condition, ctx)
			if err != nil {
				// Fail closed for allow conditions - if we can't evaluate, skip this allow
				log.Printf("Warning: Failed to evaluate session policy allow condition (policy %s): %v (skipping this allow)", sessionPolicy.ID, err)
				continue
			}
			if !matched {
				// Conditions didn't match, allow doesn't apply
				continue
			}
		}

		// Found an explicit allow
		hasExplicitAllow = true
		break
	}

	// Step 2: If no explicit allow found, action is implicitly denied by session policy
	if !hasExplicitAllow {
		return true
	}

	// Step 3: Check for explicit deny (deny overrides allow)
	for _, stmt := range sessionPolicy.Statements {
		if stmt.Effect != types.EffectDeny {
			continue
		}

		actions := normalizeToSlice(stmt.Action)
		resources := normalizeToSlice(stmt.Resource)

		// Check if action matches
		actionMatches := false
		for _, sessionAction := range actions {
			if policy.MatchesAction(sessionAction, action) {
				actionMatches = true
				break
			}
		}

		if !actionMatches {
			continue
		}

		// Check if resource matches
		resourceMatches := false
		for _, sessionResource := range resources {
			if matchesPattern(sessionResource, resourceARN) {
				resourceMatches = true
				break
			}
		}

		if !resourceMatches {
			continue
		}

		// Check conditions if present
		if len(stmt.Condition) > 0 {
			matched, err := conditions.Evaluate(stmt.Condition, ctx)
			if err != nil {
				// Fail closed for deny conditions - if we can't evaluate, treat as deny
				log.Printf("Warning: Failed to evaluate session policy deny condition (policy %s): %v (treating as deny)", sessionPolicy.ID, err)
				return true
			}
			if !matched {
				// Conditions didn't match, deny doesn't apply
				continue
			}
		}

		// Explicit deny found
		return true
	}

	// Has explicit allow and no explicit deny
	return false
}

// isRootUser checks if the ARN represents the root user
// Root user ARN format: arn:aws:iam::123456789012:root
func isRootUser(arn string) bool {
	if len(arn) < 5 {
		return false
	}
	// Check for ":root" suffix (minimum 5 chars)
	if len(arn) >= 5 && arn[len(arn)-5:] == ":root" {
		return true
	}
	// Check for ":root/" suffix (minimum 6 chars)
	if len(arn) >= 6 && arn[len(arn)-6:] == ":root/" {
		return true
	}
	return false
}

// filterSCPsForAccount filters SCPs to only those that apply to the given account
// SCPs can be attached to:
// 1. The account directly (ACCOUNT target)
// 2. The root of the organization (ROOT target) - applies to all accounts
// 3. An OU containing the account (ORGANIZATIONAL_UNIT target)
//
// This implementation uses the OU hierarchy (if available) to accurately determine
// which SCPs apply. If OU hierarchy is not available, it conservatively includes
// all OU-attached SCPs to avoid missing denies.
func filterSCPsForAccount(accountID string, attachments []types.SCPAttachment, ouHierarchy *types.OUHierarchy) []types.PolicyDocument {
	var filteredSCPs []types.PolicyDocument

	// Build set of parent OUs for fast lookup
	parentOUs := make(map[string]bool)
	if ouHierarchy != nil {
		for _, ouID := range ouHierarchy.ParentOUs {
			parentOUs[ouID] = true
		}
	}

	for _, attachment := range attachments {
		appliesToAccount := false

		for _, target := range attachment.Targets {
			switch target.Type {
			case types.SCPTargetTypeRoot:
				// SCPs attached to root apply to all accounts
				appliesToAccount = true

			case types.SCPTargetTypeAccount:
				// Check if this SCP is attached directly to our account
				if target.ID == accountID {
					appliesToAccount = true
				}

			case types.SCPTargetTypeOrganizationalUnit:
				if ouHierarchy != nil {
					// Check if this OU is in our hierarchy (we're a member of it)
					if parentOUs[target.ID] {
						appliesToAccount = true
					}
				} else {
					// No OU hierarchy available - conservatively include all OU-attached SCPs
					// This may result in false positives (reporting denies that don't apply)
					// but is safer than false negatives (missing denies that do apply)
					appliesToAccount = true
				}
			}

			if appliesToAccount {
				break
			}
		}

		if appliesToAccount {
			filteredSCPs = append(filteredSCPs, attachment.Policy)
		}
	}

	return filteredSCPs
}
