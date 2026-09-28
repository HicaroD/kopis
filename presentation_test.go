package kopis

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func presentationResult(status string) ScanResult {
	return ScanResult{
		Repositories: []RepositoryResult{{Repository: Repository{Provider: GitHubProvider, ID: "team/repo", URL: "https://user:password@example.test/team/repo"}, Status: status}},
		Findings:     []Finding{{Provider: GitHubProvider, Repository: "team/repo", Path: "opencode.json", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Indicator: "api_key", Location: Location{StartLine: 3, EndLine: 3}, Guidance: "rotate or revoke"}},
	}
}

func TestPresentationKeepsTerminalAndJSONLRedactedSemantics(t *testing.T) {
	result := presentationResult(RepositoryNoFindings)
	var terminal, jsonl bytes.Buffer
	if err := WriteTerminal(&terminal, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONL(&jsonl, result); err != nil {
		t.Fatal(err)
	}
	if terminal.String() == "" || !strings.Contains(terminal.String(), "HIGH literal_candidate api_key") {
		t.Fatalf("terminal output omitted finding semantics: %q", terminal.String())
	}
	var decoded Presentation
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonl.String())), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Severity != SeverityHigh || decoded.Findings[0].Classification != ClassificationLiteralCandidate || decoded.ExitCode != 0 {
		t.Fatalf("JSONL semantics differ: %+v", decoded)
	}
	for _, output := range []string{terminal.String(), jsonl.String()} {
		if strings.Contains(output, "password") || strings.Contains(output, "user:") {
			t.Fatalf("protected URL crossed output boundary: %q", output)
		}
	}
}

func TestIncompleteRepositoryProducesNonZeroOutcomeInBothFormats(t *testing.T) {
	result := presentationResult(RepositoryPartial)
	if ExitCode(result) == 0 {
		t.Fatal("partial scan must be unsuccessful")
	}
	var output bytes.Buffer
	if err := WriteJSONL(&output, result); err != nil {
		t.Fatal(err)
	}
	var decoded Presentation
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Complete || decoded.ExitCode == 0 || decoded.Repositories[0].Status != RepositoryPartial {
		t.Fatalf("incomplete result was presented as complete: %+v", decoded)
	}
}

func TestPresentationFailsClosedForMalformedCredentialURL(t *testing.T) {
	result := presentationResult(RepositoryNoFindings)
	result.Repositories[0].Repository.URL = "https://user:%zz@example.test/repository"
	result.Findings[0].RepositoryURL = result.Repositories[0].Repository.URL
	var terminal, jsonl bytes.Buffer
	if err := WriteTerminal(&terminal, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONL(&jsonl, result); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{terminal.String(), jsonl.String()} {
		if strings.Contains(output, "user:") || strings.Contains(output, "%zz") {
			t.Fatalf("malformed credential URL leaked: %q", output)
		}
	}
}

func TestTerminalGroupsRepeatedFindingsAndKeepsEveryLocation(t *testing.T) {
	result := ScanResult{
		Repositories: []RepositoryResult{{Repository: Repository{Provider: GitHubProvider, ID: "team/repo"}, Status: RepositoryFindings, Findings: make([]Finding, 3)}},
		Findings: []Finding{
			{Provider: GitHubProvider, Repository: "team/repo", Path: ".claude/settings.json", Tool: ToolClaudeCode, CatalogRule: "claude.settings", Indicator: "password", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Fingerprint: "synthetic-fingerprint", Location: Location{StartLine: 24, StartByte: 420, EndLine: 24, EndByte: 436}, Guidance: "rotate or revoke"},
			{Provider: GitHubProvider, Repository: "team/repo", Path: ".claude/settings.json", Tool: ToolClaudeCode, CatalogRule: "claude.settings", Indicator: "password", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Fingerprint: "synthetic-fingerprint", Location: Location{StartLine: 15, StartByte: 120, EndLine: 15, EndByte: 136}, Guidance: "rotate or revoke"},
			{Provider: GitHubProvider, Repository: "team/repo", Path: ".claude/settings.json", Tool: ToolClaudeCode, CatalogRule: "claude.settings", Indicator: "password", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Fingerprint: "synthetic-fingerprint", Location: Location{StartLine: 16, StartByte: 270, EndLine: 16, EndByte: 286}, Guidance: "rotate or revoke"},
		},
	}
	var terminal, jsonl bytes.Buffer
	if err := WriteTerminal(&terminal, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONL(&jsonl, result); err != nil {
		t.Fatal(err)
	}
	text := terminal.String()
	if strings.Count(text, "synthetic-fingerprint") != 1 || strings.Count(text, "rotate or revoke") != 1 || !strings.Contains(text, "3 occurrences") || !strings.Contains(text, "status: findings") {
		t.Fatalf("terminal output did not group repeated findings: %q", text)
	}
	for _, location := range []string{"15:120-136", "16:270-286", "24:420-436"} {
		if !strings.Contains(text, location) {
			t.Fatalf("missing source location %s in %q", location, text)
		}
	}
	if strings.Index(text, "15:120-136") > strings.Index(text, "24:420-436") {
		t.Fatalf("locations not ordered: %q", text)
	}
	var decoded Presentation
	if err := json.Unmarshal(jsonl.Bytes(), &decoded); err != nil || len(decoded.Findings) != 3 {
		t.Fatalf("JSONL lost individual findings: %+v err=%v", decoded, err)
	}
}

func TestTerminalKeepsDistinctCredentialsSeparate(t *testing.T) {
	result := ScanResult{
		Repositories: []RepositoryResult{{Repository: Repository{Provider: GitHubProvider, ID: "team/repo"}, Status: RepositoryFindings, Findings: make([]Finding, 2)}},
		Findings: []Finding{
			{Provider: GitHubProvider, Repository: "team/repo", Path: ".claude/settings.json", CatalogRule: "claude.settings", Indicator: "password", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Fingerprint: "first-fingerprint", Location: Location{StartLine: 2, EndLine: 2}},
			{Provider: GitHubProvider, Repository: "team/repo", Path: ".claude/settings.json", CatalogRule: "claude.settings", Indicator: "password", Classification: ClassificationLiteralCandidate, Severity: SeverityHigh, Fingerprint: "second-fingerprint", Location: Location{StartLine: 3, EndLine: 3}},
		},
	}
	var output bytes.Buffer
	if err := WriteTerminal(&output, result); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "(1 occurrence)") != 2 || !strings.Contains(output.String(), "first-fingerprint") || !strings.Contains(output.String(), "second-fingerprint") {
		t.Fatalf("distinct credentials were collapsed: %q", output.String())
	}
}
