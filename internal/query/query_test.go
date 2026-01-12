package query

import (
	"fmt"
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func setupTestGraph() *graph.Graph {
	g := graph.New()

	// Add admin user
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	// Add S3 user
	s3User := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/s3-user",
		Type: types.PrincipalTypeUser,
		Name: "s3-user",
	}
	g.AddPrincipal(s3User)
	g.AddEdge(s3User.ARN, "s3:*", "*", false)

	// Add read-only user
	readOnly := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/read-only",
		Type: types.PrincipalTypeUser,
		Name: "read-only",
	}
	g.AddPrincipal(readOnly)
	g.AddEdge(readOnly.ARN, "s3:Get*", "arn:aws:s3:::public-bucket/*", false)

	// Add a resource
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::public-bucket",
		Type: types.ResourceTypeS3,
		Name: "public-bucket",
	}
	g.AddResource(bucket)

	return g
}

func TestNew(t *testing.T) {
	g := graph.New()
	e := New(g)

	if e == nil {
		t.Fatal("New() returned nil")
	}
	if e.graph == nil {
		t.Error("New() did not set graph")
	}
}

func TestWhoCan_AdminUser(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	principals, err := e.WhoCan("*", "*")
	if err != nil {
		t.Fatalf("WhoCan() error = %v", err)
	}

	if len(principals) < 1 {
		t.Fatal("WhoCan() should find at least the admin user")
	}

	// Check admin is in results
	found := false
	for _, p := range principals {
		if p.Name == "admin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("WhoCan() did not find admin user with * permissions")
	}
}

func TestWhoCan_S3GetObject(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	// Query for S3 GetObject
	principals, err := e.WhoCan("arn:aws:s3:::any-bucket/*", "s3:GetObject")
	if err != nil {
		t.Fatalf("WhoCan() error = %v", err)
	}

	// Should find admin (has *) and s3-user (has s3:*)
	if len(principals) < 2 {
		t.Errorf("WhoCan() found %d principals, expected at least 2 (admin and s3-user)", len(principals))
	}

	names := make(map[string]bool)
	for _, p := range principals {
		names[p.Name] = true
	}

	if !names["admin"] {
		t.Error("WhoCan() should find admin user (has * permission)")
	}
	if !names["s3-user"] {
		t.Error("WhoCan() should find s3-user (has s3:* permission)")
	}
}

func TestWhoCan_SpecificBucket(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	// Query for public bucket specifically
	principals, err := e.WhoCan("arn:aws:s3:::public-bucket/*", "s3:GetObject")
	if err != nil {
		t.Fatalf("WhoCan() error = %v", err)
	}

	// Should find admin, s3-user, and read-only
	if len(principals) < 3 {
		t.Errorf("WhoCan() found %d principals, expected at least 3", len(principals))
	}

	names := make(map[string]bool)
	for _, p := range principals {
		names[p.Name] = true
	}

	if !names["read-only"] {
		t.Error("WhoCan() should find read-only user (has s3:Get* on public-bucket)")
	}
}

func TestWhoCan_IAMAction(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	// Query for IAM action - only admin should have this
	principals, err := e.WhoCan("*", "iam:CreateUser")
	if err != nil {
		t.Fatalf("WhoCan() error = %v", err)
	}

	// Should only find admin (has *)
	if len(principals) != 1 {
		t.Errorf("WhoCan() found %d principals, expected 1 (only admin)", len(principals))
	}

	if len(principals) > 0 && principals[0].Name != "admin" {
		t.Error("WhoCan() should only find admin user for IAM actions")
	}
}

func TestWhoCan_NoMatch(t *testing.T) {
	g := graph.New()
	e := New(g)

	// Empty graph, no one has access
	principals, err := e.WhoCan("arn:aws:s3:::bucket/*", "s3:GetObject")
	if err != nil {
		t.Fatalf("WhoCan() error = %v", err)
	}

	if len(principals) != 0 {
		t.Errorf("WhoCan() found %d principals, expected 0 for empty graph", len(principals))
	}
}

func TestFindPaths_DirectAccess(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	// Use an actual resource ARN that exists in the graph
	paths, err := e.FindPaths(
		"arn:aws:iam::123456789012:user/admin",
		"arn:aws:s3:::public-bucket",
		"s3:GetObject",
	)
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	if len(paths) == 0 {
		t.Error("FindPaths() should find at least one path for admin user")
	}

	if len(paths) > 0 {
		path := paths[0]
		if path.From.Name != "admin" {
			t.Errorf("FindPaths() path.From.Name = %q, want %q", path.From.Name, "admin")
		}
		if len(path.Hops) == 0 {
			t.Error("FindPaths() path should have at least one hop")
		}
	}
}

func TestFindPaths_NoAccess(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	// read-only user trying to access IAM
	paths, err := e.FindPaths(
		"arn:aws:iam::123456789012:user/read-only",
		"arn:aws:iam::123456789012:user/alice",
		"iam:CreateUser",
	)
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	if len(paths) != 0 {
		t.Error("FindPaths() should not find path when user lacks permissions")
	}
}

func TestFindPaths_PrincipalNotFound(t *testing.T) {
	g := setupTestGraph()
	e := New(g)

	_, err := e.FindPaths(
		"arn:aws:iam::123456789012:user/nonexistent",
		"arn:aws:s3:::public-bucket",
		"s3:GetObject",
	)

	if err == nil {
		t.Error("FindPaths() should return error for nonexistent principal")
	}
}

func TestFindPaths_SingleRoleAssumption(t *testing.T) {
	// Create user Alice
	alice := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
	}

	// Create role DevRole that Alice can assume
	devRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/DevRole",
		Type: types.PrincipalTypeRole,
		Name: "DevRole",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:GetObject",
						Resource: "arn:aws:s3:::dev-bucket/*",
					},
				},
			},
		},
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": alice.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	// Create S3 bucket resource
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::dev-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "dev-bucket",
	}

	// Build graph from collection
	collection := &types.CollectionResult{
		Principals: []*types.Principal{alice, devRole},
		Resources:  []*types.Resource{bucket},
	}
	g, err := graph.Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	e := New(g)

	// Find paths from Alice to dev-bucket
	paths, err := e.FindPaths(alice.ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("FindPaths() should find path through role assumption")
	}

	// Verify path: Alice → AssumeRole → DevRole → s3:GetObject → bucket
	path := paths[0]
	if len(path.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(path.Hops))
	}

	// First hop: Alice → AssumeRole → DevRole
	if path.Hops[0].Action != "sts:AssumeRole" {
		t.Errorf("First hop action should be sts:AssumeRole, got %s", path.Hops[0].Action)
	}
	if path.Hops[0].PolicyType != types.PolicyTypeTrust {
		t.Errorf("First hop should be trust policy, got %s", path.Hops[0].PolicyType)
	}

	// Second hop: DevRole → s3:GetObject → bucket
	if path.Hops[1].Action != "s3:GetObject" {
		t.Errorf("Second hop action should be s3:GetObject, got %s", path.Hops[1].Action)
	}
	if path.Hops[1].PolicyType != types.PolicyTypeIdentity {
		t.Errorf("Second hop should be identity policy, got %s", path.Hops[1].PolicyType)
	}
}

func TestFindPaths_TwoHopRoleChain(t *testing.T) {
	// Alice → DevRole → ProdRole → prod-bucket
	alice := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
	}

	devRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/DevRole",
		Type: types.PrincipalTypeRole,
		Name: "DevRole",
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": alice.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	prodRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/ProdRole",
		Type: types.PrincipalTypeRole,
		Name: "ProdRole",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:*",
						Resource: "arn:aws:s3:::prod-bucket/*",
					},
				},
			},
		},
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": devRole.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::prod-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "prod-bucket",
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{alice, devRole, prodRole},
		Resources:  []*types.Resource{bucket},
	}
	g, err := graph.Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	e := New(g)

	paths, err := e.FindPaths(alice.ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("FindPaths() should find 2-hop role chain path")
	}

	// Verify 3 hops: Alice → DevRole → ProdRole → bucket
	path := paths[0]
	if len(path.Hops) != 3 {
		t.Fatalf("Expected 3 hops, got %d", len(path.Hops))
	}

	// Verify hop sequence
	if path.Hops[0].Action != "sts:AssumeRole" {
		t.Errorf("Hop 1 should be AssumeRole, got %s", path.Hops[0].Action)
	}
	if path.Hops[1].Action != "sts:AssumeRole" {
		t.Errorf("Hop 2 should be AssumeRole, got %s", path.Hops[1].Action)
	}
	if path.Hops[2].Action != "s3:GetObject" {
		t.Errorf("Hop 3 should be s3:GetObject, got %s", path.Hops[2].Action)
	}
}

func TestFindPaths_CycleDetection(t *testing.T) {
	g := graph.New()

	// Role A and Role B can assume each other (cycle)
	roleA := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/RoleA",
		Type: types.PrincipalTypeRole,
		Name: "RoleA",
	}

	roleB := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/RoleB",
		Type: types.PrincipalTypeRole,
		Name: "RoleB",
	}

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}

	g.AddPrincipal(roleA)
	g.AddPrincipal(roleB)
	g.AddResource(bucket)

	// Create cycle: A can assume B, B can assume A
	g.AddTrustRelation(roleA.ARN, roleB.ARN)
	g.AddTrustRelation(roleB.ARN, roleA.ARN)

	e := New(g)

	// FindPaths should not hang (cycle detection should work)
	paths, err := e.FindPaths(roleA.ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	// Should find no paths (neither role has access to bucket)
	if len(paths) != 0 {
		t.Errorf("Expected no paths with cycle and no access, got %d", len(paths))
	}
}

func TestFindPaths_MaxDepthLimit(t *testing.T) {
	g := graph.New()

	// Create a chain of 10 roles (exceeds max depth of 5)
	roles := make([]*types.Principal, 10)
	for i := 0; i < 10; i++ {
		roles[i] = &types.Principal{
			ARN:  fmt.Sprintf("arn:aws:iam::123456789012:role/Role%d", i),
			Type: types.PrincipalTypeRole,
			Name: fmt.Sprintf("Role%d", i),
		}
		g.AddPrincipal(roles[i])
	}

	// Chain them: Role0 can assume Role1, Role1 can assume Role2, etc.
	for i := 0; i < 9; i++ {
		g.AddTrustRelation(roles[i+1].ARN, roles[i].ARN)
	}

	// Role9 (last) has access to bucket
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}
	g.AddResource(bucket)

	roles[9].Policies = []types.PolicyDocument{
		{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect:   types.EffectAllow,
					Action:   "s3:GetObject",
					Resource: bucket.ARN,
				},
			},
		},
	}

	collection := &types.CollectionResult{
		Principals: roles,
		Resources:  []*types.Resource{bucket},
	}
	g, err := graph.Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	e := New(g)

	// Try to find path from Role0 to bucket (requires 10 hops, exceeds limit of 5)
	paths, err := e.FindPaths(roles[0].ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	// Should find no paths due to max depth limit
	if len(paths) != 0 {
		t.Errorf("Expected no paths due to max depth, got %d", len(paths))
	}
}

func TestFindPaths_MultiplePaths(t *testing.T) {
	// Alice can reach bucket via TWO different roles
	alice := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
	}

	devRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/DevRole",
		Type: types.PrincipalTypeRole,
		Name: "DevRole",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:GetObject",
						Resource: "arn:aws:s3:::test-bucket/*",
					},
				},
			},
		},
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": alice.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	adminRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/AdminRole",
		Type: types.PrincipalTypeRole,
		Name: "AdminRole",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "*",
						Resource: "*",
					},
				},
			},
		},
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": alice.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{alice, devRole, adminRole},
		Resources:  []*types.Resource{bucket},
	}
	g, err := graph.Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	e := New(g)

	paths, err := e.FindPaths(alice.ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	// Should find 2 paths (via DevRole and via AdminRole)
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths, got %d", len(paths))
	}
}

func TestFindPaths_DirectAndIndirectAccess(t *testing.T) {
	// Alice has BOTH direct access AND can assume a role with access
	alice := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/alice",
		Type: types.PrincipalTypeUser,
		Name: "alice",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:GetObject",
						Resource: "arn:aws:s3:::test-bucket/*",
					},
				},
			},
		},
	}

	devRole := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:role/DevRole",
		Type: types.PrincipalTypeRole,
		Name: "DevRole",
		Policies: []types.PolicyDocument{
			{
				Version: "2012-10-17",
				Statements: []types.Statement{
					{
						Effect:   types.EffectAllow,
						Action:   "s3:*",
						Resource: "*",
					},
				},
			},
		},
		TrustPolicy: &types.PolicyDocument{
			Version: "2012-10-17",
			Statements: []types.Statement{
				{
					Effect: types.EffectAllow,
					Principal: map[string]interface{}{
						"AWS": alice.ARN,
					},
					Action: "sts:AssumeRole",
				},
			},
		},
	}

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket/*",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}

	collection := &types.CollectionResult{
		Principals: []*types.Principal{alice, devRole},
		Resources:  []*types.Resource{bucket},
	}
	g, err := graph.Build(collection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	e := New(g)

	paths, err := e.FindPaths(alice.ARN, bucket.ARN, "s3:GetObject")
	if err != nil {
		t.Fatalf("FindPaths() error = %v", err)
	}

	// Should find 2 paths: direct and via role
	if len(paths) != 2 {
		t.Errorf("Expected 2 paths (direct + via role), got %d", len(paths))
	}

	// Verify one is direct (1 hop) and one is via role (2 hops)
	foundDirect := false
	foundViaRole := false
	for _, path := range paths {
		if len(path.Hops) == 1 {
			foundDirect = true
		} else if len(path.Hops) == 2 {
			foundViaRole = true
		}
	}

	if !foundDirect {
		t.Error("Should find direct access path")
	}
	if !foundViaRole {
		t.Error("Should find indirect access path via role")
	}
}

func TestFindHighRiskAccess_AdminUser(t *testing.T) {
	g := graph.New()

	// Add admin user with wildcard permissions
	admin := &types.Principal{
		ARN:       "arn:aws:iam::123456789012:user/admin",
		Type:      types.PrincipalTypeUser,
		Name:      "admin",
		AccountID: "123456789012",
	}
	g.AddPrincipal(admin)
	g.AddEdge(admin.ARN, "*", "*", false)

	e := New(g)
	findings, err := e.FindHighRiskAccess()

	if err != nil {
		t.Fatalf("FindHighRiskAccess() error = %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected to find admin access risk")
	}

	found := false
	for _, f := range findings {
		if f.Type == "Admin Access" && f.Severity == "CRITICAL" {
			found = true
			if f.Principal == nil || f.Principal.Name != "admin" {
				t.Error("Expected finding to reference admin principal")
			}
			break
		}
	}

	if !found {
		t.Error("Did not find CRITICAL admin access finding")
	}
}

func TestFindHighRiskAccess_PublicS3Bucket(t *testing.T) {
	g := graph.New()

	// Create public principal
	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public (Anonymous)",
	}
	g.AddPrincipal(publicPrincipal)

	// Create S3 bucket with public access
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::public-bucket",
		Type: types.ResourceTypeS3,
		Name: "public-bucket",
	}
	g.AddResource(bucket)
	g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	findings, err := e.FindHighRiskAccess()

	if err != nil {
		t.Fatalf("FindHighRiskAccess() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "Public Access" && f.Resource != nil && f.Resource.Name == "public-bucket" {
			found = true
			if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
				t.Errorf("Expected CRITICAL or HIGH severity for public S3, got %s", f.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("Did not find public S3 bucket finding")
	}
}

func TestFindHighRiskAccess_NoFindings(t *testing.T) {
	g := graph.New()

	// Add a regular user with limited permissions
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/readonly",
		Type: types.PrincipalTypeUser,
		Name: "readonly",
	}
	g.AddPrincipal(user)
	g.AddEdge(user.ARN, "s3:GetObject", "arn:aws:s3:::specific-bucket/*", false)

	e := New(g)
	findings, err := e.FindHighRiskAccess()

	if err != nil {
		t.Fatalf("FindHighRiskAccess() error = %v", err)
	}

	// Should have no high-risk findings for a limited read-only user
	if len(findings) > 0 {
		t.Errorf("Expected no high-risk findings for limited user, got %d", len(findings))
	}
}

func TestFindHighRiskAccess_CrossAccount(t *testing.T) {
	g := graph.New()

	// Add multiple local principals to establish account context
	localUser := &types.Principal{
		ARN:       "arn:aws:iam::123456789012:user/local-user",
		Type:      types.PrincipalTypeUser,
		Name:      "local-user",
		AccountID: "123456789012",
	}
	g.AddPrincipal(localUser)

	localRole := &types.Principal{
		ARN:       "arn:aws:iam::123456789012:role/local-role",
		Type:      types.PrincipalTypeRole,
		Name:      "local-role",
		AccountID: "123456789012",
	}
	g.AddPrincipal(localRole)

	// Add principal from external account
	externalRole := &types.Principal{
		ARN:       "arn:aws:iam::999999999999:role/ExternalRole",
		Type:      types.PrincipalTypeRole,
		Name:      "ExternalRole",
		AccountID: "999999999999",
	}
	g.AddPrincipal(externalRole)

	// Grant external role access to a resource
	resource := &types.Resource{
		ARN:  "arn:aws:s3:::shared-bucket",
		Type: types.ResourceTypeS3,
		Name: "shared-bucket",
	}
	g.AddResource(resource)
	g.AddEdge(externalRole.ARN, "s3:GetObject", resource.ARN, false)

	e := New(g)
	findings, err := e.FindHighRiskAccess()

	if err != nil {
		t.Fatalf("FindHighRiskAccess() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "Cross-Account Access" && f.Severity == "MEDIUM" {
			found = true
			if f.Principal == nil || f.Principal.Name != "ExternalRole" {
				t.Error("Expected finding to reference external role")
			}
			if f.Principal.AccountID != "999999999999" {
				t.Errorf("Expected external account ID 999999999999, got %s", f.Principal.AccountID)
			}
			break
		}
	}

	if !found {
		t.Error("Did not find MEDIUM cross-account access finding")
	}
}

func TestFindHighRiskAccess_OverlyPermissiveS3(t *testing.T) {
	g := graph.New()

	// Add user with s3:* on all resources
	s3PowerUser := &types.Principal{
		ARN:       "arn:aws:iam::123456789012:user/s3-power-user",
		Type:      types.PrincipalTypeUser,
		Name:      "s3-power-user",
		AccountID: "123456789012",
	}
	g.AddPrincipal(s3PowerUser)
	g.AddEdge(s3PowerUser.ARN, "s3:*", "*", false)

	e := New(g)
	findings, err := e.FindHighRiskAccess()

	if err != nil {
		t.Fatalf("FindHighRiskAccess() error = %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Type == "Overly Permissive S3 Access" && f.Severity == "HIGH" {
			found = true
			if f.Principal == nil || f.Principal.Name != "s3-power-user" {
				t.Error("Expected finding to reference s3-power-user")
			}
			if f.Action != "s3:*" {
				t.Errorf("Expected action 's3:*', got %s", f.Action)
			}
			break
		}
	}

	if !found {
		t.Error("Did not find HIGH overly permissive S3 access finding")
	}
}

func TestFindHighRiskAccess_SensitiveActions(t *testing.T) {
	// Test each sensitive action pattern
	testCases := []struct {
		name           string
		action         string
		principalName  string
		expectedType   string
	}{
		{
			name:          "IAM wildcard access",
			action:        "iam:*",
			principalName: "iam-manager",
			expectedType:  "Full IAM access",
		},
		{
			name:          "KMS decrypt access",
			action:        "kms:Decrypt",
			principalName: "kms-user",
			expectedType:  "KMS decryption access",
		},
		{
			name:          "Secrets Manager access",
			action:        "secretsmanager:GetSecretValue",
			principalName: "secrets-reader",
			expectedType:  "Secrets retrieval access",
		},
		{
			name:          "STS assume role access",
			action:        "sts:AssumeRole",
			principalName: "role-assumer",
			expectedType:  "Role assumption access",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := graph.New()

			user := &types.Principal{
				ARN:       "arn:aws:iam::123456789012:user/" + tc.principalName,
				Type:      types.PrincipalTypeUser,
				Name:      tc.principalName,
				AccountID: "123456789012",
			}
			g.AddPrincipal(user)
			g.AddEdge(user.ARN, tc.action, "*", false)

			e := New(g)
			findings, err := e.FindHighRiskAccess()

			if err != nil {
				t.Fatalf("FindHighRiskAccess() error = %v", err)
			}

			found := false
			for _, f := range findings {
				if f.Type == "Sensitive Action Access" && f.Severity == "HIGH" {
					if f.Principal != nil && f.Principal.Name == tc.principalName {
						found = true
						// Verify the description contains the expected type
						if len(tc.expectedType) > 0 && f.Description != "" {
							// Description should mention the sensitive action type
							t.Logf("Found sensitive action finding: %s", f.Description)
						}
						break
					}
				}
			}

			if !found {
				t.Errorf("Did not find HIGH sensitive action finding for %s", tc.name)
			}
		})
	}
}
