package query

import (
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/graph"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestGenerateAccessMatrix(t *testing.T) {
	g := graph.New()

	// Add principals
	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/test-user",
		Type: types.PrincipalTypeUser,
		Name: "test-user",
	}
	g.AddPrincipal(user)

	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)

	// Add resources
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}
	g.AddResource(bucket)

	// Grant access
	g.AddEdge(user.ARN, "s3:GetObject", bucket.ARN, false)
	g.AddEdge(admin.ARN, "*", "*", false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"s3:GetObject", "*"})

	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	if len(matrix.Principals) != 2 {
		t.Errorf("Expected 2 principals, got %d", len(matrix.Principals))
	}

	if len(matrix.Resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(matrix.Resources))
	}

	// Check user access
	userCell := matrix.Grid[user.ARN][bucket.ARN]
	if !userCell.HasAccess {
		t.Error("User should have access to bucket")
	}

	if len(userCell.AllowedActions) == 0 {
		t.Error("User should have at least one allowed action")
	}

	// Check admin access
	adminCell := matrix.Grid[admin.ARN][bucket.ARN]
	if !adminCell.HasAccess {
		t.Error("Admin should have access to bucket")
	}

	if !adminCell.IsPrivileged {
		t.Error("Admin access should be marked as privileged")
	}

	// Check summary
	if matrix.Summary.TotalPrincipals != 2 {
		t.Errorf("Summary: expected 2 principals, got %d", matrix.Summary.TotalPrincipals)
	}

	if matrix.Summary.TotalResources != 1 {
		t.Errorf("Summary: expected 1 resource, got %d", matrix.Summary.TotalResources)
	}

	if matrix.Summary.TotalAccessGrants == 0 {
		t.Error("Summary: expected at least one access grant")
	}
}

func TestGenerateAccessMatrix_PublicAccess(t *testing.T) {
	g := graph.New()

	// Add public principal
	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public (Anonymous)",
	}
	g.AddPrincipal(publicPrincipal)

	// Add resource
	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::public-bucket",
		Type: types.ResourceTypeS3,
		Name: "public-bucket",
	}
	g.AddResource(bucket)

	// Grant public access
	g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"s3:GetObject"})

	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	// Check public access
	publicCell := matrix.Grid[publicPrincipal.ARN][bucket.ARN]
	if !publicCell.IsPublic {
		t.Error("Public access should be marked as IsPublic")
	}

	if publicCell.AccessVia != "public" {
		t.Errorf("AccessVia should be 'public', got '%s'", publicCell.AccessVia)
	}

	if matrix.Summary.PublicResources == 0 {
		t.Error("Summary should report public resources")
	}
}

func TestGetAccessibleResources(t *testing.T) {
	g := graph.New()

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user",
		Type: types.PrincipalTypeUser,
		Name: "user",
	}
	g.AddPrincipal(user)

	bucket1 := &types.Resource{
		ARN:  "arn:aws:s3:::bucket1",
		Type: types.ResourceTypeS3,
		Name: "bucket1",
	}
	g.AddResource(bucket1)

	bucket2 := &types.Resource{
		ARN:  "arn:aws:s3:::bucket2",
		Type: types.ResourceTypeS3,
		Name: "bucket2",
	}
	g.AddResource(bucket2)

	bucket3 := &types.Resource{
		ARN:  "arn:aws:s3:::bucket3",
		Type: types.ResourceTypeS3,
		Name: "bucket3",
	}
	g.AddResource(bucket3)

	// Grant access to bucket1 and bucket2
	g.AddEdge(user.ARN, "s3:GetObject", bucket1.ARN, false)
	g.AddEdge(user.ARN, "s3:GetObject", bucket2.ARN, false)

	e := New(g)
	accessible, err := e.GetAccessibleResources(user.ARN, "s3:GetObject")

	if err != nil {
		t.Fatalf("GetAccessibleResources() error = %v", err)
	}

	if len(accessible) != 2 {
		t.Errorf("Expected 2 accessible resources, got %d", len(accessible))
	}

	// Verify correct resources
	found := make(map[string]bool)
	for _, r := range accessible {
		found[r.ARN] = true
	}

	if !found[bucket1.ARN] || !found[bucket2.ARN] {
		t.Error("Should find bucket1 and bucket2")
	}

	if found[bucket3.ARN] {
		t.Error("Should not find bucket3 (no access)")
	}
}

func TestGetPrincipalsWithAccess(t *testing.T) {
	g := graph.New()

	user1 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user1",
		Type: types.PrincipalTypeUser,
		Name: "user1",
	}
	g.AddPrincipal(user1)

	user2 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user2",
		Type: types.PrincipalTypeUser,
		Name: "user2",
	}
	g.AddPrincipal(user2)

	user3 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user3",
		Type: types.PrincipalTypeUser,
		Name: "user3",
	}
	g.AddPrincipal(user3)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::shared-bucket",
		Type: types.ResourceTypeS3,
		Name: "shared-bucket",
	}
	g.AddResource(bucket)

	// Grant access to user1 and user2
	g.AddEdge(user1.ARN, "s3:GetObject", bucket.ARN, false)
	g.AddEdge(user2.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	principals, err := e.GetPrincipalsWithAccess(bucket.ARN, "s3:GetObject")

	if err != nil {
		t.Fatalf("GetPrincipalsWithAccess() error = %v", err)
	}

	if len(principals) != 2 {
		t.Errorf("Expected 2 principals with access, got %d", len(principals))
	}

	// Verify correct principals
	found := make(map[string]bool)
	for _, p := range principals {
		found[p.ARN] = true
	}

	if !found[user1.ARN] || !found[user2.ARN] {
		t.Error("Should find user1 and user2")
	}

	if found[user3.ARN] {
		t.Error("Should not find user3 (no access)")
	}
}

func TestGeneratePrincipalAccessReport(t *testing.T) {
	g := graph.New()

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/test-user",
		Type: types.PrincipalTypeUser,
		Name: "test-user",
	}
	g.AddPrincipal(user)

	bucket1 := &types.Resource{
		ARN:  "arn:aws:s3:::bucket1",
		Type: types.ResourceTypeS3,
		Name: "bucket1",
	}
	g.AddResource(bucket1)

	bucket2 := &types.Resource{
		ARN:  "arn:aws:s3:::bucket2",
		Type: types.ResourceTypeS3,
		Name: "bucket2",
	}
	g.AddResource(bucket2)

	// Grant access
	g.AddEdge(user.ARN, "s3:GetObject", bucket1.ARN, false)
	g.AddEdge(user.ARN, "s3:PutObject", bucket2.ARN, false)

	e := New(g)
	report, err := e.GeneratePrincipalAccessReport(user.ARN)

	if err != nil {
		t.Fatalf("GeneratePrincipalAccessReport() error = %v", err)
	}

	if report.Principal.ARN != user.ARN {
		t.Errorf("Expected principal %s, got %s", user.ARN, report.Principal.ARN)
	}

	if report.TotalResourcesAccessible != 2 {
		t.Errorf("Expected 2 accessible resources, got %d", report.TotalResourcesAccessible)
	}

	// Check bucket1 access
	access1, ok := report.Resources[bucket1.ARN]
	if !ok {
		t.Error("Should have access to bucket1")
	}

	if !access1.HasAccess {
		t.Error("Should have HasAccess=true for bucket1")
	}

	if len(access1.AllowedActions) == 0 {
		t.Error("Should have allowed actions for bucket1")
	}
}

func TestGenerateResourceAccessReport(t *testing.T) {
	g := graph.New()

	user1 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user1",
		Type: types.PrincipalTypeUser,
		Name: "user1",
	}
	g.AddPrincipal(user1)

	user2 := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user2",
		Type: types.PrincipalTypeUser,
		Name: "user2",
	}
	g.AddPrincipal(user2)

	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public",
	}
	g.AddPrincipal(publicPrincipal)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::shared-bucket",
		Type: types.ResourceTypeS3,
		Name: "shared-bucket",
	}
	g.AddResource(bucket)

	// Grant access
	g.AddEdge(user1.ARN, "s3:GetObject", bucket.ARN, false)
	g.AddEdge(user2.ARN, "s3:PutObject", bucket.ARN, false)
	g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	report, err := e.GenerateResourceAccessReport(bucket.ARN)

	if err != nil {
		t.Fatalf("GenerateResourceAccessReport() error = %v", err)
	}

	if report.Resource.ARN != bucket.ARN {
		t.Errorf("Expected resource %s, got %s", bucket.ARN, report.Resource.ARN)
	}

	if report.TotalPrincipalsWithAccess != 3 {
		t.Errorf("Expected 3 principals with access, got %d", report.TotalPrincipalsWithAccess)
	}

	if !report.IsPubliclyAccessible {
		t.Error("Should be marked as publicly accessible")
	}

	// Check public access
	publicAccess, ok := report.Principals[publicPrincipal.ARN]
	if !ok {
		t.Error("Should have public principal in report")
	}

	if !publicAccess.IsPublic {
		t.Error("Public principal should have IsPublic=true")
	}
}

func TestFilterPublicAccess(t *testing.T) {
	g := graph.New()

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user",
		Type: types.PrincipalTypeUser,
		Name: "user",
	}
	g.AddPrincipal(user)

	publicPrincipal := &types.Principal{
		ARN:  "*",
		Type: types.PrincipalTypePublic,
		Name: "Public",
	}
	g.AddPrincipal(publicPrincipal)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::bucket",
		Type: types.ResourceTypeS3,
		Name: "bucket",
	}
	g.AddResource(bucket)

	g.AddEdge(user.ARN, "s3:GetObject", bucket.ARN, false)
	g.AddEdge(publicPrincipal.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"s3:GetObject"})
	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	filtered := matrix.FilterPublicAccess()

	// Should only contain public principal
	foundPublic := false
	foundUser := false

	for principalARN := range filtered.Grid {
		for resourceARN, cell := range filtered.Grid[principalARN] {
			if cell.HasAccess {
				if principalARN == publicPrincipal.ARN && resourceARN == bucket.ARN {
					foundPublic = true
				}
				if principalARN == user.ARN {
					foundUser = true
				}
			}
		}
	}

	if !foundPublic {
		t.Error("Filtered matrix should contain public access")
	}

	if foundUser {
		t.Error("Filtered matrix should not contain non-public access")
	}
}

func TestFilterPrivilegedAccess(t *testing.T) {
	g := graph.New()

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user",
		Type: types.PrincipalTypeUser,
		Name: "user",
	}
	g.AddPrincipal(user)

	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::bucket",
		Type: types.ResourceTypeS3,
		Name: "bucket",
	}
	g.AddResource(bucket)

	g.AddEdge(user.ARN, "s3:GetObject", bucket.ARN, false)
	g.AddEdge(admin.ARN, "*", "*", false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"s3:GetObject", "*"})
	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	filtered := matrix.FilterPrivilegedAccess()

	// Should only contain admin
	foundAdmin := false
	foundUser := false

	for principalARN := range filtered.Grid {
		for _, cell := range filtered.Grid[principalARN] {
			if cell.HasAccess && cell.IsPrivileged {
				if principalARN == admin.ARN {
					foundAdmin = true
				}
			}
			if cell.HasAccess && !cell.IsPrivileged {
				if principalARN == user.ARN {
					foundUser = true
				}
			}
		}
	}

	if !foundAdmin {
		t.Error("Filtered matrix should contain privileged (admin) access")
	}

	if foundUser {
		t.Error("Filtered matrix should not contain non-privileged access")
	}
}

func TestGetDenseRegions(t *testing.T) {
	g := graph.New()

	// Add principals
	admin := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}
	g.AddPrincipal(admin)

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/user",
		Type: types.PrincipalTypeUser,
		Name: "user",
	}
	g.AddPrincipal(user)

	// Add resources
	bucket1 := &types.Resource{ARN: "arn:aws:s3:::bucket1", Type: types.ResourceTypeS3, Name: "bucket1"}
	bucket2 := &types.Resource{ARN: "arn:aws:s3:::bucket2", Type: types.ResourceTypeS3, Name: "bucket2"}
	g.AddResource(bucket1)
	g.AddResource(bucket2)

	// Admin has access to everything
	g.AddEdge(admin.ARN, "*", "*", false)

	// User has limited access
	g.AddEdge(user.ARN, "s3:GetObject", bucket1.ARN, false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"*", "s3:GetObject"})
	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	regions := matrix.GetDenseRegions(0.5) // 50% threshold

	if len(regions) == 0 {
		t.Error("Expected at least one dense region")
	}

	// Admin should be a dense region (100% access)
	foundAdmin := false
	for _, region := range regions {
		if region.Type == "principal" && region.PrincipalARN == admin.ARN {
			foundAdmin = true
			if region.AccessDensity != 1.0 {
				t.Errorf("Expected admin density 1.0, got %.2f", region.AccessDensity)
			}
		}
	}

	if !foundAdmin {
		t.Error("Should identify admin as dense region")
	}
}

func TestExportToCSV(t *testing.T) {
	g := graph.New()

	user := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/test-user",
		Type: types.PrincipalTypeUser,
		Name: "test-user",
	}
	g.AddPrincipal(user)

	bucket := &types.Resource{
		ARN:  "arn:aws:s3:::test-bucket",
		Type: types.ResourceTypeS3,
		Name: "test-bucket",
	}
	g.AddResource(bucket)

	g.AddEdge(user.ARN, "s3:GetObject", bucket.ARN, false)

	e := New(g)
	matrix, err := e.GenerateAccessMatrix([]string{"s3:GetObject"})
	if err != nil {
		t.Fatalf("GenerateAccessMatrix() error = %v", err)
	}

	csv := matrix.ExportToCSV()

	if len(csv) < 2 {
		t.Error("CSV should have at least header + 1 data row")
	}

	// Check header
	if csv[0][0] != "Principal" {
		t.Errorf("First header cell should be 'Principal', got '%s'", csv[0][0])
	}

	// Check that we have data rows
	if len(csv[1]) == 0 {
		t.Error("Data row should not be empty")
	}
}
