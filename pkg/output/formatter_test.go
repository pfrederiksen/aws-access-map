package output

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/pfrederiksen/aws-access-map/internal/query"
	"github.com/pfrederiksen/aws-access-map/pkg/types"
)

func TestPrintWhoCan_JSON(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	principals := []*types.Principal{
		{
			ARN:       "arn:aws:iam::123456789012:user/admin",
			Type:      types.PrincipalTypeUser,
			Name:      "admin",
			AccountID: "123456789012",
		},
		{
			ARN:       "arn:aws:iam::123456789012:role/AppRole",
			Type:      types.PrincipalTypeRole,
			Name:      "AppRole",
			AccountID: "123456789012",
		},
	}

	err := PrintWhoCan("json", "arn:aws:s3:::bucket/*", "s3:GetObject", principals)
	if err != nil {
		t.Fatalf("PrintWhoCan() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Parse JSON to verify it's valid
	var output WhoCanOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, buf.String())
	}

	// Verify fields
	if output.Resource != "arn:aws:s3:::bucket/*" {
		t.Errorf("Expected resource 'arn:aws:s3:::bucket/*', got '%s'", output.Resource)
	}

	if output.Action != "s3:GetObject" {
		t.Errorf("Expected action 's3:GetObject', got '%s'", output.Action)
	}

	if len(output.Principals) != 2 {
		t.Fatalf("Expected 2 principals, got %d", len(output.Principals))
	}

	if output.Principals[0].Name != "admin" {
		t.Errorf("Expected first principal name 'admin', got '%s'", output.Principals[0].Name)
	}

	if output.Principals[0].Type != "user" {
		t.Errorf("Expected first principal type 'user', got '%s'", output.Principals[0].Type)
	}
}

func TestPrintWhoCan_Text(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	principals := []*types.Principal{
		{
			ARN:  "arn:aws:iam::123456789012:user/admin",
			Type: types.PrincipalTypeUser,
			Name: "admin",
		},
	}

	err := PrintWhoCan("text", "arn:aws:s3:::bucket/*", "s3:GetObject", principals)
	if err != nil {
		t.Fatalf("PrintWhoCan() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if buf.Len() == 0 {
		t.Error("Expected non-empty text output")
	}

	// Should contain the principal name
	if !bytes.Contains(buf.Bytes(), []byte("admin")) {
		t.Error("Expected output to contain 'admin'")
	}
}

func TestPrintWhoCan_EmptyPrincipals(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := PrintWhoCan("text", "arn:aws:s3:::bucket/*", "s3:GetObject", []*types.Principal{})
	if err != nil {
		t.Fatalf("PrintWhoCan() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if !bytes.Contains(buf.Bytes(), []byte("No principals found")) {
		t.Error("Expected 'No principals found' message")
	}
}

func TestPrintPaths_JSON(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fromPrincipal := &types.Principal{
		ARN:  "arn:aws:iam::123456789012:user/admin",
		Type: types.PrincipalTypeUser,
		Name: "admin",
	}

	toResource := &types.Resource{
		ARN:  "arn:aws:s3:::bucket",
		Type: types.ResourceTypeS3,
		Name: "bucket",
	}

	paths := []*types.AccessPath{
		{
			From:   fromPrincipal,
			To:     toResource,
			Action: "s3:GetObject",
			Hops: []types.AccessHop{
				{
					From:       fromPrincipal,
					To:         toResource,
					Action:     "s3:GetObject",
					PolicyType: types.PolicyTypeIdentity,
				},
			},
		},
	}

	err := PrintPaths("json", fromPrincipal.ARN, toResource.ARN, "s3:GetObject", paths)
	if err != nil {
		t.Fatalf("PrintPaths() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Parse JSON to verify it's valid
	var output PathsOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, buf.String())
	}

	// Verify fields
	if output.From != fromPrincipal.ARN {
		t.Errorf("Expected from '%s', got '%s'", fromPrincipal.ARN, output.From)
	}

	if output.To != toResource.ARN {
		t.Errorf("Expected to '%s', got '%s'", toResource.ARN, output.To)
	}

	if len(output.Paths) != 1 {
		t.Fatalf("Expected 1 path, got %d", len(output.Paths))
	}

	if len(output.Paths[0].Hops) != 1 {
		t.Fatalf("Expected 1 hop, got %d", len(output.Paths[0].Hops))
	}
}

func TestPrintReport_JSON(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	findings := []query.HighRiskFinding{
		{
			Type:        "Admin Access",
			Severity:    "CRITICAL",
			Description: "User has wildcard permissions",
			Principal: &types.Principal{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
				Name: "admin",
			},
			Action: "*",
		},
	}

	err := PrintReport("json", "123456789012", findings)
	if err != nil {
		t.Fatalf("PrintReport() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Parse JSON to verify it's valid
	var output ReportOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, buf.String())
	}

	// Verify fields
	if output.AccountID != "123456789012" {
		t.Errorf("Expected account ID '123456789012', got '%s'", output.AccountID)
	}

	if len(output.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(output.Findings))
	}

	if output.Findings[0].Type != "Admin Access" {
		t.Errorf("Expected finding type 'Admin Access', got '%s'", output.Findings[0].Type)
	}

	if output.Findings[0].Severity != "CRITICAL" {
		t.Errorf("Expected severity 'CRITICAL', got '%s'", output.Findings[0].Severity)
	}

	if output.GeneratedAt == "" {
		t.Error("Expected non-empty GeneratedAt timestamp")
	}
}

func TestPrintReport_NoFindings(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := PrintReport("text", "123456789012", []query.HighRiskFinding{})
	if err != nil {
		t.Fatalf("PrintReport() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if !bytes.Contains(buf.Bytes(), []byte("No high-risk findings")) {
		t.Error("Expected 'No high-risk findings' message")
	}
}
