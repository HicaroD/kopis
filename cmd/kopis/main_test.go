package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kopis "github.com/HicaroD/kopis"
)

func TestRuntimeProviderPaginatesDefaultDiscovery(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if provider == "github" {
					if r.URL.Query().Get("page") == "1" && r.URL.Query().Get("affiliation") != "owner,collaborator,organization_member" {
						t.Fatalf("default GitHub scope was not requested: %s", r.URL.RawQuery)
					}
					if r.URL.Query().Get("page") == "1" {
						w.Header().Set("Link", "<"+"http://"+r.Host+"/user/repos?page=2>; rel=\"next\"")
					}
					_ = json.NewEncoder(w).Encode([]map[string]any{{"full_name": "team/" + r.URL.Query().Get("page"), "html_url": "https://github.test/repo"}})
					return
				}
				if r.URL.Query().Get("page") == "1" {
					w.Header().Set("X-Next-Page", "2")
				}
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "path_with_namespace": "team/" + r.URL.Query().Get("page"), "web_url": "https://gitlab.test/repo", "visibility": "private"}})
			}))
			defer server.Close()
			providerClient := runtimeProvider{provider: provider, token: "runtime-token", baseURL: server.URL}
			repositories, err := providerClient.Discover(context.Background(), "runtime-token")
			if err != nil || len(repositories) != 2 {
				t.Fatalf("default discovery did not exhaust pages: repositories=%+v err=%v", repositories, err)
			}
		})
	}
}

func TestNoScopeCrawlsPublicRepositoriesInBoundedResumableBatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			if r.URL.Query().Get("since") == "" {
				w.Header().Set("Link", "<http://"+r.Host+"/repositories?since=2>; rel=\"next\"")
				_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"},{"id":2,"full_name":"public/two"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":3,"full_name":"public/three"}]`))
			}
		case "/user/repos":
			t.Error("no-scope crawl used token-associated discovery")
			http.NotFound(w, r)
		case "/repos/public/one", "/repos/public/two", "/repos/public/three":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main", "/repos/public/two/commits/main", "/repos/public/three/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree", "/repos/public/two/git/trees/tree", "/repos/public/three/git/trees/tree":
			_, _ = w.Write([]byte(`{"tree":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	checkpoint := filepath.Join(t.TempDir(), "checkpoint.json")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", checkpoint, "-batch-size", "1", "-format", "jsonl"}
	for index, wantComplete := range []bool{false, false, true} {
		var output, diagnostic bytes.Buffer
		status := run(args, strings.NewReader(""), &output, &diagnostic)
		var report kopis.Presentation
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatalf("batch %d: invalid report %q: %v; stderr=%q", index, output.String(), err, diagnostic.String())
		}
		if report.Complete != wantComplete || len(report.Repositories) != 1 || report.Repositories[0].Repository != []string{"public/one", "public/two", "public/three"}[index] {
			t.Fatalf("batch %d: wrong coverage or resumed repository: %+v stderr=%q", index, report, diagnostic.String())
		}
		if (status == 0) != wantComplete {
			t.Fatalf("batch %d: exit code %d for complete=%t", index, status, wantComplete)
		}
	}
}

func TestChangedInspectorDoesNotResumeEarlierCoverageCheckpoint(t *testing.T) {
	oldCatalog, err := json.Marshal(kopis.InitialCatalog())
	if err != nil {
		t.Fatal(err)
	}
	oldFingerprint := sha256.Sum256(oldCatalog)
	path := filepath.Join(t.TempDir(), "old.json")
	data, err := json.Marshal(crawlCheckpoint{Version: checkpointVersion, Provider: "github", Instance: "https://api.github.com", Catalog: fmt.Sprintf("%x", oldFingerprint), LastID: 531})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCrawl(path, "github", "https://api.github.com", catalogIdentity(kopis.InitialCatalog())); err == nil {
		t.Fatal("an earlier detector checkpoint would silently skip repositories requiring a rescan")
	}
}

func TestFormatAwareInspectorInvalidatesPreviousCheckpoint(t *testing.T) {
	catalog, err := json.Marshal(kopis.InitialCatalog())
	if err != nil {
		t.Fatal(err)
	}
	previous := sha256.Sum256(append([]byte("json-structured-v2:"), catalog...))
	path := filepath.Join(t.TempDir(), "previous.json")
	data, err := json.Marshal(crawlCheckpoint{Version: checkpointVersion, Provider: "github", Instance: "https://api.github.com", Catalog: fmt.Sprintf("%x", previous)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCrawl(path, "github", "https://api.github.com", catalogIdentity(kopis.InitialCatalog())); err == nil {
		t.Fatal("old detector checkpoint would skip format-aware reinspection")
	}
}

func TestLoopbackClassificationInvalidatesPreviousCheckpoint(t *testing.T) {
	catalog, err := json.Marshal(kopis.InitialCatalog())
	if err != nil {
		t.Fatal(err)
	}
	previous := sha256.Sum256(append([]byte("format-aware-v3:"), catalog...))
	path := filepath.Join(t.TempDir(), "previous.json")
	data, err := json.Marshal(crawlCheckpoint{Version: checkpointVersion, Provider: "github", Instance: "https://api.github.com", Catalog: fmt.Sprintf("%x", previous)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCrawl(path, "github", "https://api.github.com", catalogIdentity(kopis.InitialCatalog())); err == nil {
		t.Fatal("previous detector checkpoint would retain outdated loopback findings")
	}
}

func TestGitHubSearchLeadsRunsNormalRepositoryScanAndReportsIncompleteCoverage(t *testing.T) {
	var unexpected []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search/code":
			if r.URL.Query().Get("q") != "filename:opencode.json" {
				t.Errorf("wrong catalog query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 2, "items": []any{
				map[string]any{"path": "opencode.json", "repository": map[string]any{"full_name": "public/one", "html_url": "https://github.com/public/one"}},
				map[string]any{"path": "notes.txt", "repository": map[string]any{"full_name": "public/other"}},
			}})
		case "/repos/public/one":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree":
			_, _ = w.Write([]byte(`{"tree":[{"path":"opencode.json","type":"blob","sha":"blob"},{"path":"notes.txt","type":"blob","sha":"other"}]}`))
		case "/repos/public/one/git/blobs/blob":
			_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(`{"api_key":"synthetic-value-123"}`))})
		default:
			unexpected = append(unexpected, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	var output, diagnostic bytes.Buffer
	code := run([]string{"-provider", "github", "-base-url", server.URL, "-search-leads", "-format", "jsonl"}, strings.NewReader(""), &output, &diagnostic)
	var report kopis.Presentation
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || code != 2 || report.Complete || len(report.Repositories) != 1 || len(report.Findings) != 1 || report.Leads == nil || report.Leads.QueriesRun != 1 || len(unexpected) != 0 {
		t.Fatalf("lead search skipped repository inspection or claimed coverage: code=%d report=%+v err=%v unexpected=%v diagnostic=%q", code, report, err, unexpected, diagnostic.String())
	}
}

func TestGitLabPublicCrawlStopsAtRecordedUpperID(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.String())
		switch r.URL.Path {
		case "/api/v4/projects":
			if r.URL.Query().Get("membership") != "" || r.URL.Query().Get("visibility") != "public" || r.URL.Query().Get("pagination") != "keyset" || r.URL.Query().Get("order_by") != "id" {
				t.Errorf("wrong public keyset query: %s", r.URL.RawQuery)
			}
			if r.URL.Query().Get("sort") == "desc" {
				_, _ = w.Write([]byte(`[{"id":2}]`))
				return
			}
			if r.URL.Query().Get("id_after") == "" {
				w.Header().Set("Link", "<http://"+r.Host+"/api/v4/projects?pagination=keyset&id_after=1>; rel=\"next\"")
				_, _ = w.Write([]byte(`[{"id":1,"path_with_namespace":"public/one","visibility":"public"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":2,"path_with_namespace":"public/two","visibility":"public"},{"id":3,"path_with_namespace":"public/new","visibility":"public"}]`))
			}
		case "/api/v4/projects/public/one", "/api/v4/projects/public/two":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/api/v4/projects/public/one/repository/commits/main", "/api/v4/projects/public/two/repository/commits/main":
			_, _ = w.Write([]byte(`{"id":"commit"}`))
		case "/api/v4/projects/public/one/repository/tree", "/api/v4/projects/public/two/repository/tree":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected public crawl request: %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITLAB_TOKEN", "runtime-token")
	checkpoint := filepath.Join(t.TempDir(), "checkpoint.json")
	args := []string{"-provider", "gitlab", "-base-url", server.URL, "-checkpoint", checkpoint, "-batch-size", "1", "-format", "jsonl"}
	for i, complete := range []bool{false, true} {
		var out, diagnostic bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &diagnostic)
		var report kopis.Presentation
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Crawl == nil || report.Crawl.EndID != 2 || report.Complete != complete || len(report.Repositories) != 1 || report.Repositories[0].Repository != []string{"public/one", "public/two"}[i] || (code == 0) != complete {
			t.Fatalf("run %d: code=%d report=%+v err=%v diagnostic=%q", i, code, report, err, diagnostic.String())
		}
	}
}

func TestPublicCrawlRetriesPartialRepositoryBeforeCompleting(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
		case "/repos/public/one":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree":
			attempts++
			if attempts == 1 {
				_, _ = w.Write([]byte(`{"truncated":true,"tree":[]}`))
			} else {
				_, _ = w.Write([]byte(`{"tree":[]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "crawl.json"), "-batch-size", "1", "-format", "jsonl"}
	for i, complete := range []bool{false, true} {
		var out, diagnostic bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &diagnostic)
		var report kopis.Presentation
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || report.Crawl == nil || report.Complete != complete || (code == 0) != complete || len(report.Repositories) != 1 {
			t.Fatalf("run %d: code=%d report=%+v err=%v diagnostic=%q", i, code, report, err, diagnostic.String())
		}
	}
	if attempts != 2 {
		t.Fatalf("expected partial repository retry, got %d attempts", attempts)
	}
}

func TestNewPassStartsAfterCompletedPublicBoundary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			if r.URL.Query().Get("since") == "1" {
				_, _ = w.Write([]byte(`[{"id":2,"full_name":"public/two"}]`))
			} else {
				_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
			}
		case "/repos/public/one", "/repos/public/two":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main", "/repos/public/two/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree", "/repos/public/two/git/trees/tree":
			_, _ = w.Write([]byte(`{"tree":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "crawl.json"), "-format", "jsonl"}
	var first, second, diagnostic bytes.Buffer
	if code := run(args, strings.NewReader(""), &first, &diagnostic); code != 0 {
		t.Fatalf("initial pass failed: code=%d stderr=%q", code, diagnostic.String())
	}
	diagnostic.Reset()
	if code := run(append(append([]string(nil), args...), "-new-pass"), strings.NewReader(""), &second, &diagnostic); code != 0 {
		t.Fatalf("next pass failed: code=%d stderr=%q", code, diagnostic.String())
	}
	var report kopis.Presentation
	if err := json.Unmarshal(second.Bytes(), &report); err != nil || !report.Complete || len(report.Repositories) != 1 || report.Repositories[0].Repository != "public/two" {
		t.Fatalf("next pass revisited previous range: %+v err=%v", report, err)
	}
}

func TestNewPassWithNoNewRepositoriesRetainsBoundary(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repositories" {
			switch {
			case r.URL.Path == "/repos/public/one":
				_, _ = w.Write([]byte(`{"default_branch":"main"}`))
			case strings.HasSuffix(r.URL.Path, "/commits/main"):
				_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
			case strings.HasSuffix(r.URL.Path, "/git/trees/tree"):
				_, _ = w.Write([]byte(`{"tree":[]}`))
			default:
				http.NotFound(w, r)
			}
			return
		}
		requests = append(requests, r.URL.Query().Get("since"))
		if r.URL.Query().Get("since") == "" {
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
		} else {
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "crawl.json"), "-format", "jsonl"}
	for i := 0; i < 3; i++ {
		var out, diagnostic bytes.Buffer
		runArgs := append([]string(nil), args...)
		if i > 0 {
			runArgs = append(runArgs, "-new-pass")
		}
		if code := run(runArgs, strings.NewReader(""), &out, &diagnostic); code != 0 {
			t.Fatalf("pass %d failed: %s", i, diagnostic.String())
		}
	}
	if strings.Join(requests, ",") != ",1,1" {
		t.Fatalf("new pass restarted the full crawl: %v", requests)
	}
}

func TestExhaustedPublicRepositoryRemainsAnIdentifiedCoverageGap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/broken"}]`))
		case "/repos/public/broken":
			w.WriteHeader(http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "crawl.json"), "-batch-size", "1", "-format", "jsonl"}
	for i := 0; i < 3; i++ {
		var out, diagnostic bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &diagnostic)
		var report kopis.Presentation
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || code != 2 || report.Complete || report.Crawl == nil {
			t.Fatalf("attempt %d: code=%d report=%+v err=%v diagnostic=%q", i, code, report, err, diagnostic.String())
		}
		if i == 2 && (report.Crawl.Gaps != 1 || len(report.Crawl.GapRepositories) != 1 || report.Crawl.GapRepositories[0] != "public/broken") {
			t.Fatalf("exhausted failure was not identified: %+v", report.Crawl)
		}
	}
}

func TestPublicRetryWaitsForAnotherRun(t *testing.T) {
	var attempted int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repositories" {
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/broken"}]`))
			return
		}
		if r.URL.Path == "/repos/public/broken" {
			attempted++
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	var out, diagnostic bytes.Buffer
	code := run([]string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "crawl.json"), "-batch-size", "100", "-format", "jsonl"}, strings.NewReader(""), &out, &diagnostic)
	if code != 2 || attempted != 1 {
		t.Fatalf("retry consumed the same run: code=%d attempts=%d stderr=%q", code, attempted, diagnostic.String())
	}
}

func TestFailedPublicDiscoveryResumesFromCommittedCursor(t *testing.T) {
	var fail bool = true
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			cursor := r.URL.Query().Get("since")
			cursors = append(cursors, cursor)
			if cursor == "" {
				w.Header().Set("Link", "<http://"+r.Host+"/repositories?since=1>; rel=\"next\"")
				_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
			} else if fail {
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				_, _ = w.Write([]byte(`[{"id":2,"full_name":"public/two"}]`))
			}
		case "/repos/public/one", "/repos/public/two":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main", "/repos/public/two/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree", "/repos/public/two/git/trees/tree":
			_, _ = w.Write([]byte(`{"tree":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	checkpoint := filepath.Join(t.TempDir(), "crawl.json")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", checkpoint, "-batch-size", "10", "-format", "jsonl"}
	for i := 0; i < 2; i++ {
		var out, diagnostic bytes.Buffer
		code := run(args, strings.NewReader(""), &out, &diagnostic)
		var report kopis.Presentation
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || (code == 0) != (i == 1) || len(report.Repositories) != 1 || report.Repositories[0].Repository != []string{"public/one", "public/two"}[i] || (i == 0 && (report.Crawl == nil || report.Crawl.DiscoveryFailure == "")) {
			t.Fatalf("run %d: code=%d report=%+v err=%v stderr=%q", i, code, report, err, diagnostic.String())
		}
		fail = false
	}
	if strings.Join(cursors, ",") != ",1,1" {
		t.Fatalf("discovery skipped or repeated committed work: %v", cursors)
	}
}

func TestFailedReportWriteRetainsCrawlFindingsForNextRun(t *testing.T) {
	var fetched int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
		case "/repos/public/one":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree":
			_, _ = w.Write([]byte(`{"tree":[{"path":"opencode.json","type":"blob","sha":"blob"}]}`))
		case "/repos/public/one/git/blobs/blob":
			fetched++
			_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("api_key=literal-secret"))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	checkpoint := filepath.Join(t.TempDir(), "checkpoint.json")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", checkpoint, "-format", "jsonl"}
	var out, diagnostic bytes.Buffer
	if code := run(append(append([]string(nil), args...), "-o", t.TempDir()), strings.NewReader(""), &out, &diagnostic); code != 1 {
		t.Fatalf("expected report write failure: %d %s", code, diagnostic.String())
	}
	out.Reset()
	diagnostic.Reset()
	if code := run(args, strings.NewReader(""), &out, &diagnostic); code != 0 {
		t.Fatalf("resume failed: %d %s", code, diagnostic.String())
	}
	var report kopis.Presentation
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Findings) != 1 || fetched != 1 {
		t.Fatalf("undelivered findings lost or rescanned: report=%+v fetches=%d err=%v", report, fetched, err)
	}
	if strings.Contains(out.String(), "literal-secret") {
		t.Fatal("checkpoint report exposed source content")
	}
}

func TestRecoveredRepositoryReplacesUndeliveredPartialStatus(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories":
			_, _ = w.Write([]byte(`[{"id":1,"full_name":"public/one"}]`))
		case "/repos/public/one":
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/public/one/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit","commit":{"tree":{"sha":"tree"}}}`))
		case "/repos/public/one/git/trees/tree":
			attempts++
			if attempts == 1 {
				_, _ = w.Write([]byte(`{"truncated":true,"tree":[]}`))
			} else {
				_, _ = w.Write([]byte(`{"tree":[]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	args := []string{"-provider", "github", "-base-url", server.URL, "-checkpoint", filepath.Join(t.TempDir(), "checkpoint.json"), "-format", "jsonl"}
	var out, diagnostic bytes.Buffer
	if code := run(append(append([]string(nil), args...), "-o", t.TempDir()), strings.NewReader(""), &out, &diagnostic); code != 1 {
		t.Fatalf("expected report failure, got %d", code)
	}
	out.Reset()
	diagnostic.Reset()
	code := run(args, strings.NewReader(""), &out, &diagnostic)
	var report kopis.Presentation
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || code != 0 || !report.Complete || len(report.Repositories) != 1 || report.Repositories[0].Status != kopis.RepositoryNoCandidateArtifacts {
		t.Fatalf("retry did not supersede partial status: code=%d report=%+v err=%v stderr=%q", code, report, err, diagnostic.String())
	}
}

func TestRunExplicitStandardInputScopeForBothProviders(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			env := "GITHUB_TOKEN"
			if provider == "gitlab" {
				env = "GITLAB_TOKEN"
			}
			if err := os.Setenv(env, "runtime-token"); err != nil {
				t.Fatal(err)
			}
			defer os.Unsetenv(env)
			var output, errors bytes.Buffer
			status := run([]string{"-provider", provider, "-base-url", server.URL, "-scope-file", "-", "-format", "jsonl"}, strings.NewReader("team/repo\n"), &output, &errors)
			if status == 0 || !strings.Contains(output.String(), "unscanned") || strings.Contains(output.String()+errors.String(), "runtime-token") {
				t.Fatalf("explicit scope journey leaked or returned success: status=%d output=%q errors=%q", status, output.String(), errors.String())
			}
		})
	}
}

func TestRunOutputFileOverwritesExistingReportWithoutWritingStdout(t *testing.T) {
	for _, format := range []string{"terminal", "jsonl"} {
		t.Run(format, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
			defer server.Close()
			t.Setenv("GITHUB_TOKEN", "runtime-token")
			path := filepath.Join(t.TempDir(), "report.txt")
			if err := os.WriteFile(path, []byte("obsolete report"), 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			status := run([]string{"-provider", "github", "-base-url", server.URL, "-scope", "team/missing", "-format", format, "-o", path}, strings.NewReader(""), &stdout, &stderr)
			content, err := os.ReadFile(path)
			if err != nil || status != 2 || stdout.Len() != 0 || strings.Contains(string(content), "obsolete report") || strings.Contains(string(content)+stderr.String(), "runtime-token") {
				t.Fatalf("report was not written safely: status=%d stdout=%q stderr=%q err=%v", status, stdout.String(), stderr.String(), err)
			}
			if !strings.Contains(stderr.String(), "preparing repository scope") {
				t.Fatal("progress did not stay on stderr")
			}
			if format == "terminal" {
				if !strings.Contains(string(content), "Scan: incomplete") {
					t.Fatalf("terminal report missing: %q", content)
				}
			} else {
				var report kopis.Presentation
				if err := json.Unmarshal(content, &report); err != nil || report.ExitCode != 2 {
					t.Fatalf("JSONL report invalid: err=%v report=%+v", err, report)
				}
			}
		})
	}
}

func TestRunOutputFileFailureDoesNotPrintReportOrReplaceDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	destination := t.TempDir()
	var stdout, stderr bytes.Buffer
	status := run([]string{"-provider", "github", "-base-url", server.URL, "-scope", "team/missing", "-o", destination}, strings.NewReader(""), &stdout, &stderr)
	if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "output failed") {
		t.Fatalf("output failure was not reported: status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
	if info, err := os.Stat(destination); err != nil || !info.IsDir() {
		t.Fatalf("destination directory was changed: %v %v", info, err)
	}
}

func TestRunExplicitScopeSearchesRepositoryOutsideDefaultDiscovery(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		for _, format := range []string{"terminal", "jsonl"} {
			t.Run(provider+"/"+format, func(t *testing.T) {
				var discoveryCalled bool
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/user/repos" || r.URL.Path == "/api/v4/projects" {
						discoveryCalled = true
						t.Fatal("explicit scope used default discovery")
					}
					if provider == "github" && r.URL.Path == "/repos/team/explicit" {
						_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "team/explicit", "html_url": "https://github.test/team/explicit", "private": false, "default_branch": "main"})
						return
					}
					if provider == "gitlab" && r.URL.Path == "/api/v4/projects/team/explicit" {
						_ = json.NewEncoder(w).Encode(map[string]any{"path_with_namespace": "team/explicit", "web_url": "https://gitlab.test/team/explicit", "visibility": "public", "default_branch": "main"})
						return
					}
					if provider == "github" && strings.HasSuffix(r.URL.Path, "/commits/main") {
						_, _ = w.Write([]byte(`{"sha":"commit-1","commit":{"tree":{"sha":"tree-1"}}}`))
						return
					}
					if provider == "github" && strings.HasSuffix(r.URL.Path, "/git/trees/tree-1") {
						_, _ = w.Write([]byte(`{"tree":[{"path":"opencode.json","type":"blob","sha":"abc123"}]}`))
						return
					}
					if provider == "github" && strings.Contains(r.URL.Path, "/git/blobs/") {
						_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("api_key=literal-secret"))})
						return
					}
					if provider == "gitlab" && strings.HasSuffix(r.URL.Path, "/repository/commits/main") {
						_, _ = w.Write([]byte(`{"id":"commit-1"}`))
						return
					}
					if provider == "gitlab" && strings.HasSuffix(r.URL.Path, "/repository/tree") {
						_, _ = w.Write([]byte(`[{"path":"opencode.json","type":"blob"}]`))
						return
					}
					if provider == "gitlab" && strings.HasSuffix(r.URL.Path, "/raw") {
						_, _ = w.Write([]byte("api_key=literal-secret"))
						return
					}
					http.NotFound(w, r)
				}))
				defer server.Close()
				env := "GITHUB_TOKEN"
				if provider == "gitlab" {
					env = "GITLAB_TOKEN"
				}
				if err := os.Setenv(env, "runtime-token"); err != nil {
					t.Fatal(err)
				}
				defer os.Unsetenv(env)
				var output, errors bytes.Buffer
				status := run([]string{"-provider", provider, "-base-url", server.URL, "-scope", "team/explicit", "-format", format}, strings.NewReader(""), &output, &errors)
				if status != 0 || discoveryCalled || !strings.Contains(output.String(), "team/explicit") || strings.Contains(output.String()+errors.String(), "literal-secret") || strings.Contains(output.String()+errors.String(), "runtime-token") {
					t.Fatalf("explicit journey failed or leaked protected data: status=%d output=%q errors=%q", status, output.String(), errors.String())
				}
			})
		}
	}
}

func TestRunExplainShowsCandidateStagesWithoutSecretContent(t *testing.T) {
	secret := "synthetic-db-pass-123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/team/explicit":
			_, _ = w.Write([]byte(`{"full_name":"team/explicit","default_branch":"main"}`))
		case "/repos/team/explicit/commits/main":
			_, _ = w.Write([]byte(`{"sha":"commit-1","commit":{"tree":{"sha":"tree-1"}}}`))
		case "/repos/team/explicit/git/trees/tree-1":
			_, _ = w.Write([]byte(`{"tree":[{"path":".claude/settings.json","type":"blob","sha":"blob-1"},{"path":"other.txt","type":"blob","sha":"blob-2"}]}`))
		case "/repos/team/explicit/git/blobs/blob-1":
			content := `{"allow":["Bash(PGPASSWORD=\"` + secret + `\" psql:*)"]}`
			_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	var output, errors bytes.Buffer
	status := run([]string{"-provider", "github", "-base-url", server.URL, "-scope", "team/explicit", "-format", "jsonl", "-explain"}, strings.NewReader(""), &output, &errors)
	if status != 0 || !strings.Contains(errors.String(), `path=".claude/settings.json" stage=inspected`) || !strings.Contains(errors.String(), "listed=2") || !strings.Contains(output.String(), "claude.settings") || !strings.Contains(output.String(), `"status":"findings"`) {
		t.Fatalf("safe handoff report missing: status=%d stdout=%q stderr=%q", status, output.String(), errors.String())
	}
	if strings.Contains(output.String()+errors.String(), secret) || strings.Contains(output.String()+errors.String(), "runtime-token") {
		t.Fatal("explain output leaked credential or token")
	}
}

func TestRunGitLabListsAndInspectsPinnedDatabaseURL(t *testing.T) {
	secret := "synthetic-db-pass-456"
	var fetched int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v4/projects/team/explicit":
			_, _ = w.Write([]byte(`{"path_with_namespace":"team/explicit","default_branch":"main"}`))
		case "/api/v4/projects/team/explicit/repository/commits/main":
			_, _ = w.Write([]byte(`{"id":"commit-1"}`))
		case "/api/v4/projects/team/explicit/repository/tree":
			if r.URL.Query().Get("ref") != "commit-1" || r.URL.Query().Get("recursive") != "true" {
				t.Error("tree was not pinned and recursive")
			}
			_, _ = w.Write([]byte(`[{"path":".claude/settings.json","type":"blob"},{"path":"other.txt","type":"blob"}]`))
		case "/api/v4/projects/team/explicit/repository/files/.claude/settings.json/raw":
			if r.URL.Query().Get("ref") != "commit-1" {
				t.Error("file was not pinned")
			}
			fetched++
			_, _ = w.Write([]byte(`{"allow":["Bash(DATABASE_URL=\"postgresql://account:` + secret + `@db.test/app\" psql:*)"]}`))
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("GITLAB_TOKEN", "runtime-token")
	var output, errors bytes.Buffer
	status := run([]string{"-provider", "gitlab", "-base-url", server.URL, "-scope", "team/explicit", "-format", "jsonl", "-explain"}, strings.NewReader(""), &output, &errors)
	if status != 0 || fetched != 1 || !strings.Contains(output.String(), "claude.settings") || !strings.Contains(errors.String(), `path=".claude/settings.json" stage=inspected`) {
		t.Fatalf("GitLab tree-to-finding journey failed: status=%d fetches=%d stdout=%q stderr=%q", status, fetched, output.String(), errors.String())
	}
	if strings.Contains(output.String()+errors.String(), secret) || strings.Contains(output.String()+errors.String(), "runtime-token") {
		t.Fatal("GitLab output leaked credential or token")
	}
}

type runtimeJourneyServer struct {
	provider       string
	mu             sync.Mutex
	queries        []string
	resolutions    []string
	defaultCalls   int
	invalidRequest string
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type progressWriter struct{ messages chan string }

func (w progressWriter) Write(p []byte) (int, error) {
	w.messages <- string(p)
	return len(p), nil
}

func TestRunReportsProgressBeforeScanCompletes(t *testing.T) {
	secondListing := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseScan := func() { releaseOnce.Do(func() { close(release) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user/repos":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"full_name": "team/one"}, {"full_name": "team/two"}})
		case strings.HasSuffix(r.URL.Path, "/git/trees/tree-1"):
			if strings.Contains(r.URL.Path, "/two/") {
				close(secondListing)
				<-release
			}
			_, _ = w.Write([]byte(`{"tree":[]}`))
		case strings.HasSuffix(r.URL.Path, "/commits/main"):
			_, _ = w.Write([]byte(`{"sha":"commit-1","commit":{"tree":{"sha":"tree-1"}}}`))
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			_, _ = w.Write([]byte(`{"default_branch":"main"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		releaseScan()
		server.Close()
	}()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	var output bytes.Buffer
	messages := make(chan string, 100)
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"-provider", "github", "-base-url", server.URL, "-token-associated", "-format", "jsonl"}, strings.NewReader(""), &output, progressWriter{messages})
	}()
	select {
	case <-secondListing:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start its second listing")
	}
	// A completed repository must report progress while another is pending.
	deadline := time.After(2 * time.Second)
waitForProgress:
	for {
		select {
		case message := <-messages:
			if strings.Contains(message, "repositories 1/2 complete") {
				break waitForProgress
			}
		case <-deadline:
			t.Fatal("completed repository reported no progress while next listing was pending")
		}
	}
	if output.Len() != 0 {
		t.Fatal("final output was written before scan completed")
	}
	releaseScan()
	select {
	case status := <-done:
		if status != 0 {
			t.Fatalf("scan returned %d", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not finish")
	}
	var result kopis.Presentation
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Repositories) != 2 {
		t.Fatalf("final JSONL output changed: %q, err=%v", output.String(), err)
	}
}

func TestRunStopsWhenProviderDiscoveryIsCanceled(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	t.Setenv("GITHUB_TOKEN", "runtime-token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output, errors bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runContext(ctx, []string{"-provider", "github", "-base-url", server.URL}, strings.NewReader(""), &output, &errors)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("provider request did not start")
	}
	cancel()
	select {
	case status := <-done:
		if status == 0 || !strings.Contains(errors.String(), "canceled") {
			t.Fatalf("canceled scan returned status=%d stderr=%q", status, errors.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceling provider discovery did not stop the CLI")
	}
}

func TestRuntimeDiscoveryHonorsHTTPTimeout(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	provider := runtimeProvider{provider: kopis.GitHubProvider, baseURL: server.URL, httpClient: &http.Client{Timeout: 50 * time.Millisecond}}
	done := make(chan error, 1)
	go func() {
		_, err := provider.Discover(context.Background(), "runtime-token")
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("discovery did not start")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("discovery did not time out")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed-out discovery did not return")
	}
}

func (s *runtimeJourneyServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r.URL.Path == "/user/repos" || r.URL.Path == "/api/v4/projects" {
		s.defaultCalls++
		if s.provider == "github" {
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"full_name": "team/complete", "html_url": "https://github.test/team/complete"},
				{"full_name": "team/partial", "html_url": "https://github.test/team/partial"},
				{"full_name": "team/denied", "html_url": "https://github.test/team/denied"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": 1, "path_with_namespace": "team/complete", "web_url": "https://gitlab.test/team/complete", "visibility": "private"},
			{"id": 2, "path_with_namespace": "team/partial", "web_url": "https://gitlab.test/team/partial", "visibility": "private"},
			{"id": 3, "path_with_namespace": "team/denied", "web_url": "https://gitlab.test/team/denied", "visibility": "private"},
		})
		return
	}

	if s.provider == "github" {
		s.github(w, r)
		return
	}
	s.gitlab(w, r)
}

func (s *runtimeJourneyServer) github(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/git/trees/tree-1") {
		if strings.Contains(r.URL.Path, "/partial/") {
			_, _ = w.Write([]byte(`{"truncated":true,"tree":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"tree":[{"path":"opencode.json","type":"blob","sha":"pinned-revision"},{"path":".mcp.json","type":"blob","sha":"pinned-revision"},{"path":".codex/config.toml","type":"blob","sha":"pinned-revision"},{"path":".agents/mcp_config.json","type":"blob","sha":"pinned-revision"},{"path":".gemini/settings.json","type":"blob","sha":"pinned-revision"}]}`))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/commits/main") {
		_, _ = w.Write([]byte(`{"sha":"pinned-revision","commit":{"tree":{"sha":"tree-1"}}}`))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/repos/") && !strings.Contains(r.URL.Path, "/git/blobs/") {
		repository := strings.TrimPrefix(r.URL.Path, "/repos/")
		if !containsString(s.resolutions, repository) {
			s.resolutions = append(s.resolutions, repository)
		}
		if strings.HasSuffix(repository, "/denied") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"full_name": repository,
			"html_url":  "https://github.test/" + repository,
			"private":   true, "default_branch": "main",
		})
		return
	}
	if strings.Contains(r.URL.Path, "/git/blobs/") {
		s.queries = append(s.queries, "team/complete blob")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encoding": "base64",
			"content":  base64.StdEncoding.EncodeToString([]byte(`api_key="literal-secret"`)),
		})
		return
	}
	s.invalidRequest = r.URL.Path
	http.NotFound(w, r)
}

func (s *runtimeJourneyServer) gitlab(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/repository/commits/main") {
		_, _ = w.Write([]byte(`{"id":"pinned-revision"}`))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/repository/tree") {
		if strings.Contains(r.URL.Path, "/partial/") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[{"path":"opencode.json","type":"blob"},{"path":".mcp.json","type":"blob"},{"path":".codex/config.toml","type":"blob"},{"path":".agents/mcp_config.json","type":"blob"},{"path":".gemini/settings.json","type":"blob"}]`))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.Contains(r.URL.Path, "/repository/") {
		repository := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
		if !containsString(s.resolutions, repository) {
			s.resolutions = append(s.resolutions, repository)
		}
		if strings.HasSuffix(repository, "/denied") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path_with_namespace": repository,
			"web_url":             "https://gitlab.test/" + repository,
			"visibility":          "private", "default_branch": "main",
		})
		return
	}
	if strings.Contains(r.URL.Path, "/repository/files/") && strings.HasSuffix(r.URL.Path, "/raw") {
		s.queries = append(s.queries, "team/complete "+strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v4/projects/team/complete/repository/files/"), "/raw"))
		_, _ = w.Write([]byte(`api_key="literal-secret"`))
		return
	}
	s.invalidRequest = r.URL.Path
	http.NotFound(w, r)
}

func (s *runtimeJourneyServer) snapshot() (defaultCalls int, resolutions, queries []string, invalid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.defaultCalls, append([]string(nil), s.resolutions...), append([]string(nil), s.queries...), s.invalidRequest
}

func TestRunCompleteAndIncompleteJourneysThroughRuntimeAdapters(t *testing.T) {
	for _, provider := range []string{"github", "gitlab"} {
		for _, scopeMode := range []string{"default", "explicit"} {
			var presentations map[string]kopis.Presentation
			for _, format := range []string{"jsonl", "terminal"} {
				journey := &runtimeJourneyServer{provider: provider}
				server := httptest.NewServer(http.HandlerFunc(journey.handler))
				env := "GITHUB_TOKEN"
				if provider == "gitlab" {
					env = "GITLAB_TOKEN"
				}
				if err := os.Setenv(env, "runtime-token"); err != nil {
					t.Fatal(err)
				}
				args := []string{"-provider", provider, "-base-url", server.URL, "-format", format}
				stdin := strings.NewReader("")
				if scopeMode == "default" {
					args = append(args, "-token-associated")
				}
				if scopeMode == "explicit" {
					args = append(args, "-scope-file", "-")
					stdin = strings.NewReader("team/complete\nteam/partial\nteam/denied\n")
				}
				var output, errors bytes.Buffer
				status := run(args, stdin, &output, &errors)
				server.Close()
				_ = os.Unsetenv(env)
				defaultCalls, resolutions, queries, invalid := journey.snapshot()
				if status != 2 || strings.Contains(errors.String(), "runtime-token") || invalid != "" {
					t.Fatalf("%s/%s/%s did not report incomplete journey: status=%d output=%q errors=%q default_calls=%d resolutions=%v invalid=%q", provider, scopeMode, format, status, output.String(), errors.String(), defaultCalls, resolutions, invalid)
				}
				if scopeMode == "default" && defaultCalls == 0 {
					t.Fatalf("%s default journey skipped authorized discovery", provider)
				}
				if scopeMode == "explicit" && (defaultCalls != 0 || len(resolutions) != 3) {
					t.Fatalf("%s explicit journey used the wrong scope path: default_calls=%d resolutions=%v", provider, defaultCalls, resolutions)
				}
				if len(queries) != 5 {
					t.Fatalf("%s/%s fetched %d files, want five: %v", provider, scopeMode, len(queries), queries)
				}
				if format == "jsonl" {
					var presentation kopis.Presentation
					if err := json.Unmarshal(output.Bytes(), &presentation); err != nil {
						t.Fatalf("%s/%s JSONL was invalid: %v", provider, scopeMode, err)
					}
					presentations = map[string]kopis.Presentation{"jsonl": presentation}
					if presentation.Complete || presentation.ExitCode != 2 || len(presentation.Repositories) != 3 || len(presentation.Findings) != 5 {
						t.Fatalf("%s/%s JSONL omitted delivery semantics: %+v", provider, scopeMode, presentation)
					}
					for _, familyPath := range []string{"opencode.json", ".mcp.json", ".codex/config.toml", ".agents/mcp_config.json", ".gemini/settings.json"} {
						found := false
						for _, finding := range presentation.Findings {
							if finding.Path == familyPath {
								found = true
							}
						}
						if !found {
							t.Fatalf("%s/%s omitted catalog family %q", provider, scopeMode, familyPath)
						}
					}
					for _, repository := range presentation.Repositories {
						if repository.Status != kopis.RepositoryFindings && repository.Status != kopis.RepositoryPartial && repository.Status != kopis.RepositoryUnscanned {
							t.Fatalf("unexpected repository status: %+v", repository)
						}
					}
					for _, finding := range presentation.Findings {
						if finding.Revision != "pinned-revision" || finding.RepositoryURL != "https://github.test/team/complete" && finding.RepositoryURL != "https://gitlab.test/team/complete" || strings.Contains(finding.RepositoryURL, "secret") || strings.Contains(finding.Reason, "literal-secret") {
							t.Fatalf("finding crossed the protected boundary: %+v", finding)
						}
					}
				} else {
					presentation := presentations["jsonl"]
					for _, marker := range []string{"Scan: incomplete", "status: findings", "status: partial", "status: unscanned", "pinned-revision"} {
						if !strings.Contains(output.String(), marker) {
							t.Fatalf("%s/%s terminal output omitted semantic marker %q: %q", provider, scopeMode, marker, output.String())
						}
					}
					if strings.Contains(output.String(), "literal-secret") || strings.Contains(output.String(), "runtime-token") || strings.Contains(output.String(), "user:secret@") {
						t.Fatalf("terminal output leaked protected data: %q", output.String())
					}
					if presentation.ExitCode != 2 || len(presentation.Findings) != 5 {
						t.Fatalf("terminal output did not match JSONL semantics: %+v", presentation)
					}
				}
			}
		}
	}
}
