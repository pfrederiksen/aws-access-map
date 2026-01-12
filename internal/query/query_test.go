package query

import (
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
