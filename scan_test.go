package kopis

import (
	"context"
	"strings"
	"sync"
	"testing"
)

type scanProvider struct {
	mu        sync.Mutex
	seenToken []string
	searches  []string
	outcomes  map[string]SearchOutcome
}

func (p *scanProvider) Discover(context.Context, string) ([]Repository, error) {
	return []Repository{
		{Provider: GitHubProvider, ID: "owner/complete", Owner: true, Accessible: true},
		{Provider: GitHubProvider, ID: "member/partial", Member: true, Accessible: true},
		{Provider: GitHubProvider, ID: "public/outside", Public: true, Accessible: true},
	}, nil
}

func (p *scanProvider) Search(_ context.Context, token string, repository Repository, query string, _ Artifact) SearchOutcome {
	p.mu.Lock()
	p.seenToken = append(p.seenToken, token)
	p.searches = append(p.searches, repository.ID+":"+query)
	p.mu.Unlock()
	return p.outcomes[repository.ID]
}

func TestScanRejectsMissingTokenBeforeDiscovery(t *testing.T) {
	provider := &scanProvider{}
	_, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Scanner: provider})
	if err == nil || len(provider.seenToken) != 0 {
		t.Fatalf("expected token preflight before provider work, err=%v", err)
	}
}

func TestScanFiltersDeduplicatesAndComposesRepositoryStatuses(t *testing.T) {
	provider := &scanProvider{outcomes: map[string]SearchOutcome{
		"owner/complete": {Complete: true, Candidates: []Candidate{
			{Provider: GitHubProvider, Repository: "owner/complete", Revision: "rev", Path: "opencode.json", Content: `provider_api_key="literal-secret"`},
			{Provider: GitHubProvider, Repository: "owner/complete", Revision: "rev", Path: "opencode.json", Content: `provider_api_key="literal-secret"`},
		}},
		"member/partial": {Complete: false},
	}}
	result, err := Scan(context.Background(), ScanRequest{
		Provider:    GitHubProvider,
		Token:       "runtime-token",
		Scanner:     provider,
		Catalog:     []Artifact{{Path: "opencode.json", Rule: CatalogRule{ID: "opencode.config", Tool: ToolOpenCode}}},
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 2 || result.Repositories[0].Status != RepositoryPartial || result.Repositories[1].Status != RepositoryNoFindings {
		t.Fatalf("unexpected repository statuses: %+v", result.Repositories)
	}
	if len(result.Findings) != 1 || result.Findings[0].Fingerprint == "" || strings.Contains(result.Findings[0].Guidance, "literal-secret") {
		t.Fatalf("expected one redacted deduplicated finding: %+v", result.Findings)
	}
	for _, token := range provider.seenToken {
		if token != "runtime-token" {
			t.Fatalf("provider received an unexpected token")
		}
	}
	for _, search := range provider.searches {
		if !strings.HasSuffix(search, "path:opencode.json") {
			t.Fatalf("search was not catalog-derived: %s", search)
		}
	}
}
