package kopis

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type scanProvider struct {
	mu           sync.Mutex
	seenToken    []string
	searches     []string
	outcomes     map[string]SearchOutcome
	repositories []Repository
	discoverErr  error
}

func (p *scanProvider) Discover(context.Context, string) ([]Repository, error) {
	if p.repositories != nil || p.discoverErr != nil {
		return p.repositories, p.discoverErr
	}
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

func TestScanExcludesDeniedDefaultRepositories(t *testing.T) {
	provider := &scanProvider{outcomes: map[string]SearchOutcome{"allowed/default": {Complete: true}}, repositories: []Repository{
		{Provider: GitHubProvider, ID: "denied/default", Owner: true, Accessible: false},
		{Provider: GitHubProvider, ID: "allowed/default", Member: true, Accessible: true},
	}}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "runtime-token", Scanner: provider, Catalog: []Artifact{{Path: "opencode.json"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 2 || result.Repositories[0].Repository.ID != "allowed/default" || result.Repositories[0].Status != RepositoryNoCandidateArtifacts || result.Repositories[1].Repository.ID != "denied/default" || result.Repositories[1].Status != RepositoryUnscanned {
		t.Fatalf("denied default repository was searched or status lost: %+v", result.Repositories)
	}
}

func TestScanDiscoveryFailurePreservesExplicitRepositoriesAsUnscanned(t *testing.T) {
	provider := &scanProvider{discoverErr: errors.New("provider unavailable")}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "runtime-token", Scanner: provider, Scope: Scope{Kind: ScopeList, RepositoryIDs: []string{"one/repo", "two/repo"}}})
	if err != nil || len(result.Repositories) != 2 {
		t.Fatalf("discovery failure lost explicit scope: result=%+v err=%v", result, err)
	}
	for _, repository := range result.Repositories {
		if repository.Status != RepositoryUnscanned {
			t.Fatalf("unexpected discovery failure status: %+v", result.Repositories)
		}
	}
}
