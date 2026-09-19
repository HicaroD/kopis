package main

import (
	"bytes"
	"context"
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
