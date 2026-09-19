package kopis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGitLabSearchPaginatesEncodesAndRetrievesPinnedFiles(t *testing.T) {
	retrievalAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escapedPath := r.URL.EscapedPath()
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			t.Fatal("request did not use the runtime token")
		}
		if escapedPath == "/api/v4/groups/team%2Fplatform/search" {
			if r.URL.Query().Get("scope") != "blobs" || r.URL.Query().Get("search") != "provider key" || r.URL.Query().Get("per_page") != "100" {
				t.Fatalf("unexpected search query: %s", r.URL.RawQuery)
			}
			page := r.URL.Query().Get("page")
			w.Header().Set("Content-Type", "application/json")
			if page == "1" {
				w.Header().Set("X-Next-Page", "2")
				_ = json.NewEncoder(w).Encode([]GitLabBlob{
					{ProjectID: "42", ProjectPath: "team/platform", ProjectWebURL: "https://gitlab.example/team/platform", Path: ".agents/skills/tool guide.md", Ref: "abc123", BlobID: "blob-a", Size: 20},
					{ProjectID: "42", ProjectPath: "team/platform", Path: ".agents/skills/tool guide.md", Ref: "abc123", BlobID: "blob-a", Size: 20},
					{ProjectID: "42", ProjectPath: "team/platform", Path: "too-large", Ref: "abc123", BlobID: "blob-b", Size: 1<<20 + 1},
				})
				return
			}
			_ = json.NewEncoder(w).Encode([]GitLabBlob{{ProjectID: "42", ProjectPath: "team/platform", ProjectWebURL: "https://gitlab.example/team/platform", Path: "second", Ref: "def456", BlobID: "blob-c", Size: 10}})
			return
		}
		if escapedPath == "/api/v4/projects/42/repository/files/.agents%2Fskills%2Ftool%20guide.md/raw" {
			if r.URL.Query().Get("ref") != "abc123" {
				t.Fatalf("retrieval was not pinned: %s", r.URL.RawQuery)
			}
			retrievalAttempts++
			if retrievalAttempts == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("pinned content"))
			return
		}
		if escapedPath == "/api/v4/projects/42/repository/files/second/raw" {
			if r.URL.Query().Get("ref") != "def456" {
				t.Fatalf("second retrieval was not pinned: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte("second content"))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "runtime-token", RetryWait: time.Millisecond, MaxRetryWait: time.Millisecond, MaxRetries: 1, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchGroup(context.Background(), "provider key", "team/platform")
	if result.Coverage.Status != GitLabPartial || !result.Coverage.IndexBoundary {
		t.Fatalf("expected partial coverage at index boundary, got %+v", result.Coverage)
	}
	if len(result.Candidates) != 2 || retrievalAttempts != 2 {
		t.Fatalf("expected two retrieved candidates and one bounded retry, got %d candidates and %d attempts", len(result.Candidates), retrievalAttempts)
	}
	if result.Candidates[0].Provider != GitLabProvider {
		t.Fatalf("unexpected provider: %+v", result.Candidates[0])
	}
}

func TestGitLabSearchPreservesPrivateNotFoundAndDoesNotRetryUnauthorized(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "token", MaxRetries: 3, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchProject(context.Background(), "key", "private/project")
	if requests != 1 || result.Coverage.Status != GitLabUnscanned || !result.Coverage.AccessAmbiguous {
		t.Fatalf("expected one privacy-preserving request, got requests=%d coverage=%+v", requests, result.Coverage)
	}
	if len(result.Failures) != 1 || !result.Failures[0].AccessAmbiguous {
		t.Fatalf("expected access ambiguity: %+v", result.Failures)
	}
}

func TestGitLabCapabilitiesDisableGlobalSearch(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()
	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, failure := client.Capabilities(context.Background())
	if failure != nil || capabilities.GlobalSearch || capabilities.IndexLimitBytes != 1<<20 || capabilities.ResultLimit != 10000 {
		t.Fatalf("unexpected capabilities: %+v, failure=%+v", capabilities, failure)
	}

	gitlabURL, _ := url.Parse("https://gitlab.com")
	client.baseURL = gitlabURL
	capabilities, failure = client.Capabilities(context.Background())
	if failure != nil || capabilities.GlobalSearch || capabilities.SelfManaged {
		t.Fatalf("unexpected GitLab.com capabilities: %+v, failure=%+v", capabilities, failure)
	}
	if strings.Contains(client.token, "Bearer") {
		t.Fatal("client stored a header instead of the raw token")
	}
}

func TestGitLabSearchLimiterCancelsAfterOneHundredRequests(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := &searchLimiter{now: func() time.Time { return now }, limit: 100, sleep: func(context.Context, time.Duration) bool { return false }}
	for i := 0; i < 100; i++ {
		if !limiter.wait(context.Background()) {
			t.Fatal("initial budget request was delayed")
		}
	}
	if limiter.wait(context.Background()) {
		t.Fatal("request 101 bypassed the shared budget")
	}
}

func TestGitLabSearchBudgetCoversRetries(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	now := time.Unix(100, 0)
	client, err := NewGitLabClient(GitLabConfig{
		BaseURL: server.URL, Token: "token", MaxRetries: 100,
		RetryWait: time.Nanosecond, MaxRetryWait: time.Nanosecond,
		Now:   func() time.Time { return now },
		Sleep: func(context.Context, time.Duration) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchProject(context.Background(), "path", "group/project")
	if requests != 100 || result.Coverage.Status != GitLabPartial || !result.Coverage.Throttled {
		t.Fatalf("retry attempts bypassed search budget: requests=%d coverage=%+v", requests, result.Coverage)
	}
}

func TestGitLabExactlyTenThousandTerminalResultsAreComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		if page < 100 {
			response.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		}
		blobs := make([]GitLabBlob, gitLabPageSize)
		for i := range blobs {
			blobs[i] = GitLabBlob{ProjectID: "42", ProjectPath: "group/project", Path: "artifact", Ref: "rev", Size: 10}
		}
		_ = json.NewEncoder(response).Encode(blobs)
	}))
	defer server.Close()
	client, err := NewGitLabClient(GitLabConfig{BaseURL: server.URL, Token: "token", Now: func() time.Time { return time.Unix(100, 0) }, Sleep: func(context.Context, time.Duration) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	result := client.SearchProject(context.Background(), "path", "group/project")
	if result.Coverage.Results != 10000 || result.Coverage.ResultCapReached || result.Coverage.Status != GitLabComplete {
		t.Fatalf("terminal ten-thousand boundary was marked partial: %+v", result.Coverage)
	}
}
