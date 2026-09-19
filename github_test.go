package kopis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubQueryValidationRejectsBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "runtime-token"})
	if err != nil {
		t.Fatal(err)
	}
	result := client.Search(context.Background(), strings.Repeat("x", githubQueryLimit+1))
	if requests.Load() != 0 || result.Coverage.Status != GitHubUnscanned || len(result.Failures) != 1 || result.Failures[0].Kind != "malformed_query" {
		t.Fatalf("expected preflight rejection, requests=%d result=%+v", requests.Load(), result)
	}
	result = client.Search(context.Background(), "path:a AND path:b OR path:c NOT path:d AND path:e OR path:f AND path:g")
	if requests.Load() != 0 || result.Failures[0].Kind != "malformed_query" {
		t.Fatalf("expected boolean-operator rejection, requests=%d result=%+v", requests.Load(), result)
	}
	result = client.Search(context.Background(), strings.Repeat("x", githubQueryLimit-1)+" unknown:qualifier")
	if requests.Load() != 0 || result.Coverage.Status != GitHubUnscanned {
		t.Fatalf("unknown colon token bypassed query limit: requests=%d result=%+v", requests.Load(), result)
	}
}

func TestGitHubSearchLimiterCancelsAfterTenRequests(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := &searchLimiter{now: func() time.Time { return now }, limit: 10, sleep: func(context.Context, time.Duration) bool { return false }}
	for i := 0; i < 10; i++ {
		if !limiter.wait(context.Background()) {
			t.Fatal("initial budget request was delayed")
		}
	}
	if limiter.wait(context.Background()) {
		t.Fatal("request 11 bypassed the shared budget")
	}
}

func TestGitHubSearchPaginatesEncodesAndRetrievesPinnedBlobs(t *testing.T) {
	var searchRequests atomic.Int32
	var retrievalRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Fatal("request did not use the runtime token")
		}
		if request.URL.Path == "/search/code" {
			if request.URL.Query().Get("q") != "path:.opencode/tools/provider guide" || request.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected search query: %s", request.URL.RawQuery)
			}
			page := searchRequests.Add(1)
			response.Header().Set("Content-Type", "application/json")
			if page == 1 {
				response.Header().Set("Link", "<"+server.URL+"/search/code?q=path%3A.opencode%2Ftools%2Fprovider+guide&per_page=100&page=2>; rel=\"next\"")
				_ = json.NewEncoder(response).Encode(map[string]any{"total_count": 2, "incomplete_results": false, "items": []any{
					map[string]any{"path": ".opencode/tools/provider guide", "sha": "abc123", "repository": map[string]string{"full_name": "team/platform", "html_url": "https://github.com/team/platform"}},
				}})
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"total_count": 2, "incomplete_results": false, "items": []any{
				map[string]any{"path": ".opencode/tools/second", "sha": "def456", "repository": map[string]string{"full_name": "team/platform", "html_url": "https://github.com/team/platform"}},
			}})
			return
		}
		if strings.HasPrefix(request.URL.Path, "/repos/team/platform/git/blobs/") {
			retrievalRequests.Add(1)
			response.Header().Set("Content-Type", "application/json")
			content := base64.StdEncoding.EncodeToString([]byte("pinned content"))
			if strings.HasSuffix(request.URL.Path, "/def456") {
				content = base64.StdEncoding.EncodeToString([]byte("second content"))
			}
			_ = json.NewEncoder(response).Encode(map[string]string{"encoding": "base64", "content": content})
			return
		}
		http.NotFound(response, request)
	}))
	defer server.Close()

	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "runtime-token", Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchCatalog(context.Background(), "path:.opencode/tools/provider guide", Artifact{Rule: CatalogRule{ID: "opencode.tool", Tool: ToolOpenCode}})
	if result.Coverage.Status != GitHubComplete || result.Coverage.Pages != 2 || result.Coverage.Results != 2 || len(result.Candidates) != 2 || retrievalRequests.Load() != 2 {
		t.Fatalf("unexpected search result: %+v", result)
	}
	for _, candidate := range result.Candidates {
		if candidate.Tool != ToolOpenCode || candidate.CatalogRule != "opencode.tool" || candidate.Revision == "" || candidate.Content == "" {
			t.Fatalf("candidate did not preserve pinned catalog identity: %+v", candidate)
		}
	}
}

func TestGitHubSearchRetriesThrottleAndPreservesIncompleteCoverage(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if requests.Add(1) == 1 {
			response.Header().Set("Retry-After", "0")
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"total_count": 1000, "incomplete_results": true, "items": []any{}})
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", MaxRetries: 1, RetryWait: time.Millisecond, MaxRetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result := client.Search(context.Background(), "path:config")
	if requests.Load() != 2 || result.Coverage.Status != GitHubPartial || !result.Coverage.IncompleteResults || !result.Coverage.ResultCapReached || len(result.Failures) != 0 {
		t.Fatalf("expected bounded retry and incomplete coverage, requests=%d coverage=%+v failures=%+v", requests.Load(), result.Coverage, result.Failures)
	}
	if !result.Coverage.DefaultBranchOnly || result.Coverage.FileSizeLimitBytes != githubFileSizeLimit || !result.Coverage.ArchivedRepositoriesExcluded || !result.Coverage.LargeRepositoriesExcluded {
		t.Fatalf("missing documented search boundaries: %+v", result.Coverage)
	}
}

func TestGitHubSearchDoesNotRetryDeniedScope(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client, err := NewGitHubClient(GitHubConfig{BaseURL: server.URL, Token: "token", MaxRetries: 3, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result := client.Search(context.Background(), "path:private")
	if requests.Load() != 1 || result.Coverage.Status != GitHubUnscanned || !result.Coverage.AccessAmbiguous || len(result.Failures) != 1 || !result.Failures[0].AccessAmbiguous {
		t.Fatalf("expected privacy-preserving unscanned result, requests=%d result=%+v", requests.Load(), result)
	}
}

func TestGitHubSearchBudgetCoversRetries(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	now := time.Unix(100, 0)
	client, err := NewGitHubClient(GitHubConfig{
		BaseURL: server.URL, Token: "token", MaxRetries: 10,
		RetryWait: time.Nanosecond, MaxRetryWait: time.Nanosecond,
		Now:   func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := client.Search(context.Background(), "path:config")
	if requests.Load() != 10 || result.Coverage.Status != GitHubPartial || !result.Coverage.Throttled {
		t.Fatalf("retry attempts bypassed search budget: requests=%d coverage=%+v", requests.Load(), result.Coverage)
	}
}
