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
	"testing"
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
