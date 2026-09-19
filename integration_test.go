package kopis

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type journeyProvider struct {
	provider string
}

func (p journeyProvider) Discover(context.Context, string) ([]Repository, error) {
	return []Repository{
		{Provider: p.provider, ID: "complete/repository", Owner: true, Accessible: true},
		{Provider: p.provider, ID: "partial/repository", Member: true, Accessible: true},
		{Provider: p.provider, ID: "denied/repository", Collaborator: true, Accessible: false},
		{Provider: p.provider, ID: "public-only/repository", Public: true, Accessible: true},
	}, nil
}

func (p journeyProvider) Search(_ context.Context, _ string, repository Repository, _ string, artifact Artifact) SearchOutcome {
	switch repository.ID {
	case "complete/repository":
		return SearchOutcome{Complete: true, Candidates: []Candidate{{Provider: p.provider, Repository: repository.ID, RepositoryURL: "https://user:secret@example.test/repository", Revision: "pinned", Path: artifact.Path, Tool: artifact.Rule.Tool, CatalogRule: artifact.Rule.ID, Content: "provider_api_key=literal-secret"}}}
	case "partial/repository":
		return SearchOutcome{Complete: false}
	default:
		return SearchOutcome{Complete: true}
	}
}

func TestDeterministicProviderJourneysReachRedactedOutputs(t *testing.T) {
	for _, provider := range []string{GitHubProvider, GitLabProvider} {
		t.Run(provider, func(t *testing.T) {
			result, err := Scan(context.Background(), ScanRequest{
				Provider:    provider,
				Token:       "runtime-token",
				Scope:       Scope{Kind: ScopeList, RepositoryIDs: []string{"complete/repository", "partial/repository", "denied/repository"}},
				Catalog:     []Artifact{{Path: "opencode.json", Rule: CatalogRule{ID: "opencode.config", Tool: ToolOpenCode}}},
				Scanner:     journeyProvider{provider: provider},
				Concurrency: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Repositories) != 3 || len(result.Findings) != 1 {
				t.Fatalf("unexpected journey result: %+v", result)
			}
			statuses := map[string]bool{}
			for _, repository := range result.Repositories {
				statuses[repository.Status] = true
			}
			for _, status := range []string{RepositoryNoFindings, RepositoryPartial, RepositoryUnscanned} {
				if !statuses[status] {
					t.Fatalf("missing status %q: %+v", status, statuses)
				}
			}
			var terminal, jsonl bytes.Buffer
			if err := WriteTerminal(&terminal, result); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSONL(&jsonl, result); err != nil {
				t.Fatal(err)
			}
			if ExitCode(result) == 0 || strings.Contains(terminal.String(), "literal-secret") || strings.Contains(jsonl.String(), "literal-secret") || strings.Contains(jsonl.String(), "runtime-token") {
				t.Fatalf("protected data or successful incomplete outcome crossed boundary: terminal=%q jsonl=%q", terminal.String(), jsonl.String())
			}
			var presentation Presentation
			if err := json.Unmarshal(jsonl.Bytes(), &presentation); err != nil || len(presentation.Findings) != 1 || presentation.Findings[0].Reason == "" {
				t.Fatalf("JSONL omitted finding semantics: %s %+v", err, presentation)
			}
		})
	}
}

func TestCatalogSubstitutionAndClaudeMarkerBoundaries(t *testing.T) {
	files := map[string]string{
		"opencode.json":               `{"instructions":["{file:secrets.txt}"]}`,
		"secrets.txt":                 "api_key=literal-secret",
		"plugins/unrelated/.mcp.json": "token=literal-secret",
	}
	opencode := RecognizeArtifact("opencode.json", files)
	if len(opencode) != 2 || opencode[0].Rule.ID != "opencode.config" || opencode[1].Rule.ID != "opencode.file-substitution" {
		t.Fatalf("config inherited target substitution rule: %+v", opencode)
	}
	if got := RecognizeArtifact("plugins/unrelated/.mcp.json", files); len(got) != 0 {
		t.Fatalf("unmarked Claude plugin was admitted: %+v", got)
	}
	files["plugins/unrelated/.claude-plugin/plugin.json"] = "{}"
	if got := RecognizeArtifact("plugins/unrelated/.mcp.json", files); len(got) != 1 || got[0].Rule.ID != "claude.plugin-mcp" {
		t.Fatalf("marker-backed Claude plugin was not admitted: %+v", got)
	}
}

func TestInspectionCredentialFormsLocationsSeverityAndExecution(t *testing.T) {
	content := "api_key=literal-api-value\npassword: literal-password\nclientSecret=literal-client-secret\n" +
		"authorization=Bearer literal-auth-value\n" +
		"api_key_default=${TOKEN:-literal-default}\nref=${TOKEN}\nplain=$TOKEN\npercent=%TOKEN%\n" +
		"fs.readFileSync(\".env\")\nreadFile(\"credentials\")\nopen(\"key.pem\")"
	findings := Inspect(Candidate{Path: "plugin.ts", CatalogRule: "opencode.plugin", Content: content})
	if len(findings) != 8 {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Location.StartByte < 0 || finding.Location.EndByte <= finding.Location.StartByte || finding.Location.StartLine < 1 {
			t.Fatalf("invalid value location: %+v", finding)
		}
		if finding.Classification == ClassificationConfirmed && finding.Fingerprint == "" {
			t.Fatalf("confirmed finding lacks fingerprint: %+v", finding)
		}
	}
	critical := 0
	medium := 0
	for _, finding := range findings {
		if finding.Severity == SeverityCritical {
			critical++
		}
		if finding.Severity == SeverityMedium {
			medium++
		}
	}
	if critical != 4 || medium != 3 {
		t.Fatalf("unexpected severity mapping: %+v", findings)
	}
}

func TestInspectionQuotedDefaultUsesLiteralLocationAndFingerprint(t *testing.T) {
	content := `api_key="${TOKEN:-literal-secret}" api_key=${TOKEN:-literal-secret}`
	findings := Inspect(Candidate{Path: "opencode.json", CatalogRule: "opencode.config", Content: content})
	if len(findings) != 2 {
		t.Fatalf("expected both quoted and unquoted defaults: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != SeverityCritical || finding.Fingerprint != fingerprint("literal-secret") {
			t.Fatalf("default was not treated as the confirmed literal: %+v", finding)
		}
		if got := content[finding.Location.StartByte:finding.Location.EndByte]; got != "literal-secret" {
			t.Fatalf("default location included expression syntax: %q", got)
		}
	}
}

func TestInspectionCredentialURLIsHighUnlessDirectField(t *testing.T) {
	findings := Inspect(Candidate{Path: "settings.json", CatalogRule: "claude.settings", Content: `url="https://user:password@safe.test/path"`})
	if len(findings) != 1 || findings[0].Indicator != "authorization_value" || findings[0].Severity != SeverityHigh {
		t.Fatalf("credential-bearing URL was over-promoted: %+v", findings)
	}
}
