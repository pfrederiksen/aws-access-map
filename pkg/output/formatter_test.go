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
	_, _ = io.Copy(&buf, r) // Ignore error in test

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
	_, _ = io.Copy(&buf, r) // Ignore error in test

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
	_, _ = io.Copy(&buf, r) // Ignore error in test

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
	_, _ = io.Copy(&buf, r) // Ignore error in test

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
	_, _ = io.Copy(&buf, r) // Ignore error in test

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
	_, _ = io.Copy(&buf, r) // Ignore error in test

	if !bytes.Contains(buf.Bytes(), []byte("No high-risk findings")) {
		t.Error("Expected 'No high-risk findings' message")
	}
}

func TestPrintCollect_JSON_WithSCPs(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &types.CollectionResult{
		AccountID: "123456789012",
		Regions:   []string{"us-east-1"},
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
				Name: "admin",
			},
		},
		Resources: []*types.Resource{
			{
				ARN:  "arn:aws:s3:::bucket",
				Type: types.ResourceTypeS3,
				Name: "bucket",
			},
		},
		SCPs: []types.PolicyDocument{
			{
				ID:      "p-abc123",
				Version: "2012-10-17",
			},
			{
				ID:      "p-def456",
				Version: "2012-10-17",
			},
		},
	}

	err := PrintCollect("json", result, "test.json")
	if err != nil {
		t.Fatalf("PrintCollect() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r) // Ignore error in test

	// Parse JSON to verify it's valid
	var output CollectOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, buf.String())
	}

	// Verify SCP fields
	if output.SCPCount != 2 {
		t.Errorf("Expected SCPCount 2, got %d", output.SCPCount)
	}

	if len(output.SCPs) != 2 {
		t.Fatalf("Expected 2 SCPs, got %d", len(output.SCPs))
	}

	if output.SCPs[0].ID != "p-abc123" {
		t.Errorf("Expected first SCP ID 'p-abc123', got '%s'", output.SCPs[0].ID)
	}
}

func TestPrintCollect_JSON_NoSCPs(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &types.CollectionResult{
		AccountID: "123456789012",
		Regions:   []string{"us-east-1"},
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
				Name: "admin",
			},
		},
		SCPs: []types.PolicyDocument{}, // Empty SCP list
	}

	err := PrintCollect("json", result, "test.json")
	if err != nil {
		t.Fatalf("PrintCollect() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r) // Ignore error in test

	// Parse JSON to verify it's valid
	var output CollectOutput
	if err := json.Unmarshal(buf.Bytes(), &output); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, buf.String())
	}

	// Verify SCP fields
	if output.SCPCount != 0 {
		t.Errorf("Expected SCPCount 0, got %d", output.SCPCount)
	}

	if len(output.SCPs) != 0 {
		t.Errorf("Expected 0 SCPs, got %d", len(output.SCPs))
	}
}

func TestPrintCollect_Text_WithSCPs(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &types.CollectionResult{
		AccountID: "123456789012",
		Principals: []*types.Principal{
			{
				ARN:  "arn:aws:iam::123456789012:user/admin",
				Type: types.PrincipalTypeUser,
				Name: "admin",
			},
		},
		Resources: []*types.Resource{},
		SCPs: []types.PolicyDocument{
			{
				ID: "p-abc123",
			},
		},
	}

	err := PrintCollect("text", result, "test.json")
	if err != nil {
		t.Fatalf("PrintCollect() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r) // Ignore error in test

	output := buf.String()

	// Verify SCP message is present
	if !bytes.Contains(buf.Bytes(), []byte("Collected 1 Service Control Policies")) {
		t.Errorf("Expected output to contain 'Collected 1 Service Control Policies', got: %s", output)
	}

	// Verify flag hint is NOT present when SCPs are collected
	if bytes.Contains(buf.Bytes(), []byte("--include-scps flag")) {
		t.Error("Expected output to NOT contain '--include-scps flag' hint when SCPs are collected")
	}
}

func TestPrintCollect_Text_NoSCPs(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := &types.CollectionResult{
		AccountID:  "123456789012",
		Principals: []*types.Principal{},
		Resources:  []*types.Resource{},
		SCPs:       []types.PolicyDocument{}, // Empty SCP list
	}

	err := PrintCollect("text", result, "test.json")
	if err != nil {
		t.Fatalf("PrintCollect() error = %v", err)
	}

	// Restore stdout and read output
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r) // Ignore error in test

	// Verify flag hint is present when SCPs are not collected
	if !bytes.Contains(buf.Bytes(), []byte("--include-scps flag")) {
		t.Error("Expected output to contain '--include-scps flag' hint when SCPs are not collected")
	}
}
