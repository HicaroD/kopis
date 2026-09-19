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
		Findings:     []Finding{{Provider: GitHubProvider, Repository: "team/repo", Path: "opencode.json", Classification: ClassificationConfirmed, Severity: SeverityHigh, Indicator: "api_key", Location: Location{StartLine: 3}, Guidance: "rotate or revoke"}},
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
	if terminal.String() == "" || !strings.Contains(terminal.String(), "confirmed high") {
		t.Fatalf("terminal output omitted finding semantics: %q", terminal.String())
	}
	var decoded Presentation
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonl.String())), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].Severity != SeverityHigh || decoded.Findings[0].Classification != ClassificationConfirmed || decoded.ExitCode != 0 {
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
