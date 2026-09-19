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
	"sync/atomic"
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
			if status == 0 || errors.Len() != 0 || !strings.Contains(output.String(), "unscanned") || strings.Contains(output.String(), "runtime-token") {
				t.Fatalf("explicit scope journey leaked or returned success: status=%d output=%q errors=%q", status, output.String(), errors.String())
			}
		})
	}
}

func TestRunExplicitScopeSearchesRepositoryOutsideDefaultDiscovery(t *testing.T) {
	installFastGitHubLimiter(t)
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
						_ = json.NewEncoder(w).Encode(map[string]any{"full_name": "team/explicit", "html_url": "https://github.test/team/explicit", "private": false})
						return
					}
					if provider == "gitlab" && strings.Contains(r.URL.Path, "/api/v4/projects/") && !strings.HasSuffix(r.URL.Path, "/search") && !strings.HasSuffix(r.URL.Path, "/raw") {
						_ = json.NewEncoder(w).Encode(map[string]any{"path_with_namespace": "team/explicit", "web_url": "https://gitlab.test/team/explicit", "visibility": "public"})
						return
					}
					if strings.HasSuffix(r.URL.Path, "/search/code") {
						_, _ = w.Write([]byte(`{"total_count":1,"incomplete_results":false,"items":[{"path":"opencode.json","sha":"abc123","html_url":"https://github.test/team/explicit/blob/abc123/opencode.json","repository":{"full_name":"team/explicit","html_url":"https://github.test/team/explicit"}}]}`))
						return
					}
					if provider == "github" && strings.Contains(r.URL.Path, "/git/blobs/") {
						_ = json.NewEncoder(w).Encode(map[string]string{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("api_key=literal-secret"))})
						return
					}
					if strings.HasSuffix(r.URL.Path, "/search") {
						_ = json.NewEncoder(w).Encode([]map[string]any{{"project_id": "42", "project_path": "team/explicit", "project_web_url": "https://gitlab.test/team/explicit", "path": "opencode.json", "ref": "main", "blob_id": "abc123", "size": 22}})
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
				if status != 0 || discoveryCalled || errors.Len() != 0 || !strings.Contains(output.String(), "team/explicit") || strings.Contains(output.String(), "literal-secret") || strings.Contains(output.String(), "runtime-token") {
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
	if strings.HasPrefix(r.URL.Path, "/repos/") && !strings.Contains(r.URL.Path, "/git/blobs/") && !strings.Contains(r.URL.Path, "/search/code") {
		repository := strings.TrimPrefix(r.URL.Path, "/repos/")
		s.resolutions = append(s.resolutions, repository)
		if strings.HasSuffix(repository, "/denied") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"full_name": repository,
			"html_url":  "https://github.test/" + repository,
			"private":   true,
		})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/search/code") {
		s.query(w, r.URL.Query().Get("q"), "github")
		return
	}
	if strings.Contains(r.URL.Path, "/git/blobs/") {
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
	if strings.HasPrefix(r.URL.Path, "/api/v4/projects/") && !strings.HasSuffix(r.URL.Path, "/search") && !strings.Contains(r.URL.Path, "/repository/files/") {
		repository := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
		repository = strings.ReplaceAll(repository, "/", "/")
		s.resolutions = append(s.resolutions, repository)
		if strings.HasSuffix(repository, "/denied") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path_with_namespace": repository,
			"web_url":             "https://gitlab.test/" + repository,
			"visibility":          "private",
		})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/search") {
		repository := strings.TrimPrefix(r.URL.Path, "/api/v4/projects/")
		s.query(w, repository+" "+r.URL.Query().Get("search"), "gitlab")
		return
	}
	if strings.Contains(r.URL.Path, "/repository/files/") && strings.HasSuffix(r.URL.Path, "/raw") {
		_, _ = w.Write([]byte("api_key=literal-secret"))
		return
	}
	s.invalidRequest = r.URL.Path
	http.NotFound(w, r)
}

func (s *runtimeJourneyServer) query(w http.ResponseWriter, query, adapter string) {
	s.queries = append(s.queries, query)
	if strings.Contains(query, "team/denied") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.Contains(query, "team/partial") {
		if adapter == "github" {
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "incomplete_results": true, "items": []any{}})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	path := catalogPath(query)
	if path == "" {
		if adapter == "github" {
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "incomplete_results": false, "items": []any{}})
		} else {
			_ = json.NewEncoder(w).Encode([]any{})
		}
		return
	}
	if adapter == "github" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total_count": 1,
			"items":       []map[string]any{{"path": path, "sha": "pinned-revision", "repository": map[string]string{"full_name": "team/complete", "html_url": "https://user:secret@github.test/team/complete"}}},
		})
		return
	}
	_ = json.NewEncoder(w).Encode([]map[string]any{{"project_id": "1", "project_path": "team/complete", "project_web_url": "https://user:secret@gitlab.test/team/complete", "path": path, "ref": "pinned-revision", "blob_id": "blob-1", "size": 22}})
}

func catalogPath(query string) string {
	for _, path := range []string{
		"opencode.json", ".mcp.json", ".codex/config.toml", ".agents/mcp_config.json", ".gemini/settings.json",
	} {
		if strings.Contains(query, path) {
			return path
		}
	}
	return ""
}

func (s *runtimeJourneyServer) snapshot() (defaultCalls int, resolutions, queries []string, invalid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.defaultCalls, append([]string(nil), s.resolutions...), append([]string(nil), s.queries...), s.invalidRequest
}

func TestRunCompleteAndIncompleteJourneysThroughRuntimeAdapters(t *testing.T) {
	installFastGitHubLimiter(t)

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
				if status != 2 || errors.Len() != 0 || invalid != "" {
					t.Fatalf("%s/%s/%s did not report incomplete journey: status=%d output=%q errors=%q default_calls=%d resolutions=%v invalid=%q", provider, scopeMode, format, status, output.String(), errors.String(), defaultCalls, resolutions, invalid)
				}
				if scopeMode == "default" && defaultCalls == 0 {
					t.Fatalf("%s default journey skipped authorized discovery", provider)
				}
				if scopeMode == "explicit" && (defaultCalls != 0 || len(resolutions) != 3) {
					t.Fatalf("%s explicit journey used the wrong scope path: default_calls=%d resolutions=%v", provider, defaultCalls, resolutions)
				}
				for _, familyPath := range []string{"opencode.json", ".mcp.json", ".codex/config.toml", ".agents/mcp_config.json", ".gemini/settings.json"} {
					if !containsQueryPath(queries, familyPath) {
						t.Fatalf("%s/%s omitted catalog family %q from runtime searches: %v", provider, scopeMode, familyPath, queries)
					}
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

func installFastGitHubLimiter(t *testing.T) {
	t.Helper()
	originalGitHubClient := newGitHubRuntimeClient
	newGitHubRuntimeClient = func(config kopis.GitHubConfig) (*kopis.GitHubClient, error) {
		var ticks int64
		config.Now = func() time.Time {
			return time.Unix(0, 0).Add(time.Duration(atomic.AddInt64(&ticks, 1)) * 2 * time.Minute)
		}
		return kopis.NewGitHubClient(config)
	}
	t.Cleanup(func() { newGitHubRuntimeClient = originalGitHubClient })
}

func containsQueryPath(queries []string, path string) bool {
	for _, query := range queries {
		if strings.Contains(query, path) && (strings.Contains(query, "team/complete") || strings.Contains(query, "team/partial") || strings.Contains(query, "team/denied")) {
			return true
		}
	}
	return false
}
