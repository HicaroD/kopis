package kopis

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type scanProvider struct {
	mu            sync.Mutex
	seenToken     []string
	searches      []string
	listings      map[string]FileListing
	repositories  []Repository
	discoverErr   error
	listing       FileListing
	contents      map[string]string
	fetched       []string
	fetchFailures map[string]bool
}

func (p *scanProvider) ListFiles(_ context.Context, token string, repository Repository) FileListing {
	p.mu.Lock()
	p.seenToken = append(p.seenToken, token)
	p.mu.Unlock()
	if p.listings != nil {
		return p.listings[repository.ID]
	}
	return p.listing
}
func (p *scanProvider) FetchFile(_ context.Context, _ string, _ Repository, file RepositoryFile) FileOutcome {
	p.mu.Lock()
	p.fetched = append(p.fetched, file.Path)
	p.mu.Unlock()
	return FileOutcome{Content: p.contents[file.Path], Complete: !p.fetchFailures[file.Path]}
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

func (p *scanProvider) Search(_ context.Context, token string, repository Repository, query string, _ Artifact) {
	p.mu.Lock()
	p.seenToken = append(p.seenToken, token)
	p.searches = append(p.searches, repository.ID+":"+query)
	p.mu.Unlock()
}

func TestScanRejectsMissingTokenBeforeDiscovery(t *testing.T) {
	provider := &scanProvider{}
	_, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Scanner: provider})
	if err == nil || len(provider.seenToken) != 0 {
		t.Fatalf("expected token preflight before provider work, err=%v", err)
	}
}

func TestScanListsPathsAndFetchesOnlyCatalogCandidates(t *testing.T) {
	provider := &scanProvider{repositories: []Repository{{Provider: GitHubProvider, ID: "team/repo", Owner: true, Accessible: true}},
		listing: FileListing{Complete: true, Files: []RepositoryFile{
			{Path: ".opencode/plugins/custom.ts", Revision: "blob-1"},
			{Path: "notes.txt", Revision: "blob-2"},
		}}, contents: map[string]string{".opencode/plugins/custom.ts": "api_key=literal-secret"}}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "runtime-token", Scanner: provider, Catalog: InitialCatalog()})
	if err != nil || len(result.Findings) != 1 || result.Findings[0].CatalogRule != "opencode.plugin" || result.Repositories[0].Status != RepositoryNoFindings {
		t.Fatalf("listing-based scan missed directory candidate: result=%+v err=%v", result, err)
	}
	if len(provider.searches) != 0 || len(provider.fetched) != 1 || provider.fetched[0] != ".opencode/plugins/custom.ts" {
		t.Fatalf("scan searched or fetched unrelated files: searches=%v fetched=%v", provider.searches, provider.fetched)
	}
}

func TestScanContentGatesAndFollowsOnlyListedSubstitutions(t *testing.T) {
	provider := &scanProvider{repositories: []Repository{{Provider: GitHubProvider, ID: "team/repo", Owner: true, Accessible: true}},
		listing: FileListing{Complete: true, Files: []RepositoryFile{
			{Path: "opencode.json", Revision: "a"}, {Path: "secrets.txt", Revision: "b"},
			{Path: ".github/workflows/build.yml", Revision: "c"}, {Path: "other.txt", Revision: "d"},
		}}, contents: map[string]string{
			"opencode.json": `{"instructions":["{file:secrets.txt}"]}`,
			"secrets.txt":   "api_key=literal-secret", ".github/workflows/build.yml": "uses: actions/checkout@v4",
		}}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "runtime-token", Scanner: provider, Catalog: InitialCatalog()})
	if err != nil || len(result.Findings) != 1 || result.Findings[0].CatalogRule != "opencode.file-substitution" {
		t.Fatalf("substitution was not catalogued: result=%+v err=%v", result, err)
	}
	if len(provider.fetched) != 3 {
		t.Fatalf("unrelated content fetched: %v", provider.fetched)
	}
}

func TestScanUnrelatedWorkflowIsNotACandidate(t *testing.T) {
	provider := &scanProvider{repositories: []Repository{{Provider: GitHubProvider, ID: "team/repo", Owner: true, Accessible: true}},
		listing:  FileListing{Complete: true, Files: []RepositoryFile{{Path: ".github/workflows/build.yml", Revision: "abc"}}},
		contents: map[string]string{".github/workflows/build.yml": "uses: actions/checkout@v4"}}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "runtime-token", Scanner: provider, Catalog: InitialCatalog()})
	if err != nil || result.Repositories[0].Status != RepositoryNoCandidateArtifacts {
		t.Fatalf("unrelated workflow counted as catalog candidate: %+v err=%v", result, err)
	}
}

func TestScanIncompleteListingOrFetchNeverClaimsFullCoverage(t *testing.T) {
	for _, failing := range []string{"listing", "fetch"} {
		t.Run(failing, func(t *testing.T) {
			provider := &scanProvider{repositories: []Repository{{Provider: GitLabProvider, ID: "team/repo", Member: true, Accessible: true}},
				listing:       FileListing{Complete: failing != "listing", Files: []RepositoryFile{{Path: "opencode.json", Revision: "commit"}, {Path: ".mcp.json", Revision: "commit"}}},
				contents:      map[string]string{"opencode.json": "api_key=literal-secret", ".mcp.json": "api_key=another-secret"},
				fetchFailures: map[string]bool{".mcp.json": failing == "fetch"},
			}
			result, err := Scan(context.Background(), ScanRequest{Provider: GitLabProvider, Token: "token", Scanner: provider, Catalog: InitialCatalog()})
			if err != nil || result.Repositories[0].Status != RepositoryPartial || len(result.Findings) == 0 {
				t.Fatalf("incomplete scan discarded findings or claimed full coverage: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestScanSubstitutionStillAppliesWhenTargetWasFetchedFirst(t *testing.T) {
	provider := &scanProvider{repositories: []Repository{{Provider: GitHubProvider, ID: "team/repo", Owner: true, Accessible: true}},
		listing: FileListing{Complete: true, Files: []RepositoryFile{{Path: ".opencode/tools/secret.ts", Revision: "blob"}, {Path: "opencode.json", Revision: "config"}}},
		contents: map[string]string{
			".opencode/tools/secret.ts": "api_key=literal-secret", "opencode.json": `{"instructions":["{file:.opencode/tools/secret.ts}"]}`,
		}}
	result, err := Scan(context.Background(), ScanRequest{Provider: GitHubProvider, Token: "token", Scanner: provider, Catalog: InitialCatalog()})
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, finding := range result.Findings {
		rules[finding.CatalogRule] = true
	}
	if !rules["opencode.tool"] || !rules["opencode.file-substitution"] || len(provider.fetched) != 2 {
		t.Fatalf("a prior fetch lost substitution attribution or fetched twice: findings=%+v fetched=%v", result.Findings, provider.fetched)
	}
}

func TestScanFiltersDeduplicatesAndComposesRepositoryStatuses(t *testing.T) {
	provider := &scanProvider{listings: map[string]FileListing{
		"owner/complete": {Complete: true, Files: []RepositoryFile{{Path: "opencode.json", Revision: "rev"}}},
		"member/partial": {Complete: false},
	}, contents: map[string]string{"opencode.json": `provider_api_key="literal-secret"`}}
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
	if len(provider.searches) != 0 {
		t.Fatalf("scan made code-search requests: %v", provider.searches)
	}
}

func TestScanExcludesDeniedDefaultRepositories(t *testing.T) {
	provider := &scanProvider{listings: map[string]FileListing{"allowed/default": {Complete: true}}, repositories: []Repository{
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
