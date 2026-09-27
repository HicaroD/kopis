package kopis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGitHubListsDefaultTreeAndFetchesPinnedBlob(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.String())
		switch r.URL.Path {
		case "/repos/team/repo":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "trunk"})
		case "/repos/team/repo/commits/trunk":
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "commit-1", "commit": map[string]any{"tree": map[string]string{"sha": "tree-1"}}})
		case "/repos/team/repo/git/trees/tree-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"truncated": false, "tree": []map[string]string{{"path": ".opencode/plugins/custom.ts", "type": "blob", "sha": "blob-1"}, {"path": "src", "type": "tree", "sha": "tree-2"}}})
		case "/repos/team/repo/git/blobs/blob-1":
			_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("api_key=literal-secret"))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	listing := client.ListFiles(context.Background(), "team/repo")
	if !listing.Complete || len(listing.Files) != 1 || listing.Files[0].Revision != "blob-1" {
		t.Fatalf("unexpected listing: %+v", listing)
	}
	file := client.FetchFile(context.Background(), "team/repo", listing.Files[0])
	if !file.Complete || file.Content != "api_key=literal-secret" {
		t.Fatalf("pinned fetch failed: %+v", file)
	}
	if !strings.Contains(strings.Join(requests, " "), "recursive=1") || strings.Contains(strings.Join(requests, " "), "/search/code") {
		t.Fatalf("tree listing used search or skipped recursion: %v", requests)
	}
}

func TestGitLabPaginatesTreeAtPinnedCommit(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.String())
		switch {
		case r.URL.Path == "/api/v4/projects/team/repo":
			_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "trunk"})
		case r.URL.Path == "/api/v4/projects/team/repo/repository/commits/trunk":
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "commit-1"})
		case strings.HasSuffix(r.URL.Path, "/repository/tree"):
			if r.URL.Query().Get("page") == "1" {
				w.Header().Set("X-Next-Page", "2")
			}
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`[{"path":"src/readme.md","type":"blob"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"path":".gemini/commands/custom.toml","type":"blob"}]`))
			}
		case strings.HasSuffix(r.URL.Path, "/repository/files/.gemini/commands/custom.toml/raw"):
			_, _ = w.Write([]byte("api_key=literal-secret"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	listing := client.ListFiles(context.Background(), "team/repo")
	if !listing.Complete || len(listing.Files) != 2 || listing.Files[1].Revision != "commit-1" {
		t.Fatalf("unexpected listing: %+v", listing)
	}
	file := client.FetchFile(context.Background(), "team/repo", listing.Files[1])
	if !file.Complete || file.Content != "api_key=literal-secret" {
		t.Fatalf("pinned fetch failed: %+v", file)
	}
	joined := strings.Join(requests, " ")
	if !strings.Contains(joined, "recursive=true") || !strings.Contains(joined, "ref=commit-1") || strings.Contains(joined, "/search") {
		t.Fatalf("tree listing was not pinned or paginated: %v", requests)
	}
}

func TestGitLabFailedLaterTreePageRetainsEarlierPathsAsIncomplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v4/projects/team/repo":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case strings.HasSuffix(r.URL.Path, "/repository/commits/main"):
			_, _ = w.Write([]byte(`{"id":"commit-1"}`))
		case strings.HasSuffix(r.URL.Path, "/repository/tree") && r.URL.Query().Get("page") == "1":
			w.Header().Set("X-Next-Page", "2")
			_, _ = w.Write([]byte(`[{"path":"opencode.json","type":"blob"}]`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	listing := client.ListFiles(context.Background(), "team/repo")
	if listing.Complete || listing.Denied || len(listing.Files) != 1 || listing.Files[0].Path != "opencode.json" {
		t.Fatalf("later-page failure lost known files or claimed complete: %+v", listing)
	}
}

func TestGitHubMalformedTreeCannotClaimNoCandidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/team/repo":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case strings.HasSuffix(r.URL.Path, "/commits/main"):
			_, _ = w.Write([]byte(`{"sha":"commit-1","commit":{"tree":{"sha":"tree-1"}}}`))
		default:
			_, _ = w.Write([]byte(`{"truncated":false}`))
		}
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if listing := client.ListFiles(context.Background(), "team/repo"); listing.Complete {
		t.Fatalf("missing tree entries claimed full coverage: %+v", listing)
	}
}
