package kopis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHubSearchLeadsOnlyCollectsCatalogRepositoriesWithoutFetchingContent(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/search/code" {
			t.Errorf("search lead discovery fetched a blob: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		queries = append(queries, r.URL.Query().Get("q"))
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 3, "items": []any{
			map[string]any{"path": "opencode.json", "repository": map[string]any{"full_name": "public/one", "html_url": "https://github.com/public/one"}},
			map[string]any{"path": "notes.txt", "repository": map[string]any{"full_name": "public/irrelevant"}},
			map[string]any{"path": "opencode.json", "repository": map[string]any{"full_name": "public/one", "html_url": "https://github.com/public/one"}},
		}})
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchLeads(context.Background(), InitialCatalog(), 0, 1)
	if result.QueriesRun != 1 || len(queries) != 1 || !strings.Contains(queries[0], "filename:opencode.json") || len(result.Repositories) != 1 || result.Repositories[0].ID != "public/one" || !result.Repositories[0].Public || result.Complete || result.RawMatches != 3 || result.EligibleMatches != 2 || result.FilteredMatches != 1 {
		t.Fatalf("lead query fetched unrelated content or claimed completeness: %+v queries=%v", result, queries)
	}
}

func TestGitHubLeadSearchFiltersDynamicPathsLocally(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 2, "items": []any{
			map[string]any{"path": ".opencode/plugins/README.md", "repository": map[string]any{"full_name": "public/docs"}},
			map[string]any{"path": ".opencode/plugins/custom.ts", "repository": map[string]any{"full_name": "public/tool"}},
		}})
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchLeads(context.Background(), InitialCatalog(), 9, 1)
	if len(result.Repositories) != 1 || result.Repositories[0].ID != "public/tool" {
		t.Fatalf("dynamic path query admitted an unrelated README: %+v", result)
	}
}

func TestGitHubLeadSearchMarksCappedQueryAndRespectsCatalog(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("q")
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1250, "incomplete_results": true, "items": []any{
			map[string]any{"path": ".mcp.json", "repository": map[string]any{"full_name": "public/one"}},
		}})
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	catalog := []Artifact{{Path: ".mcp.json", Rule: CatalogRule{ID: "claude.mcp", Tool: ToolClaudeCode}}}
	result := client.SearchLeads(context.Background(), catalog, 0, 1)
	if query != "filename:.mcp.json" || result.QueriesPlanned != 1 || len(result.Saturated) != 1 || result.Complete {
		t.Fatalf("indexed search cap or catalog boundary hidden: result=%+v query=%s", result, query)
	}
}

func TestGitHubLeadSearchCanInspectLaterResultPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("later search page not requested: %s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 101, "items": []any{
			map[string]any{"path": "opencode.json", "repository": map[string]any{"full_name": "public/later"}},
		}})
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchLeadsAt(context.Background(), InitialCatalog(), 0, 1, 2)
	if len(result.Repositories) != 1 || result.Repositories[0].ID != "public/later" || result.QueriesRun != 1 {
		t.Fatalf("indexed result pagination lost lead: %+v", result)
	}
}
