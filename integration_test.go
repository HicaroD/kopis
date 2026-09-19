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
