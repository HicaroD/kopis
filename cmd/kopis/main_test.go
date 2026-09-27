package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
		done <- run([]string{"-provider", "github", "-base-url", server.URL, "-format", "jsonl"}, strings.NewReader(""), &output, progressWriter{messages})
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
			"content":  base64.StdEncoding.EncodeToString([]byte("api_key=literal-secret")),
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
		_, _ = w.Write([]byte("api_key=literal-secret"))
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
						if repository.Status != kopis.RepositoryNoFindings && repository.Status != kopis.RepositoryPartial && repository.Status != kopis.RepositoryUnscanned {
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
					for _, marker := range []string{"complete=false", "status=no_findings", "status=partial", "status=unscanned", "pinned-revision"} {
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
