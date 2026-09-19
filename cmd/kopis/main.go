package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	kopis "github.com/HicaroD/kopis"
)

type runtimeProvider struct {
	provider string
	token    string
	baseURL  string
	github   *kopis.GitHubClient
	gitlab   *kopis.GitLabClient
}

func (p runtimeProvider) Discover(ctx context.Context, token string) ([]kopis.Repository, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.baseURL, "/")+p.discoveryPath(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("provider repository discovery failed")
	}
	if p.provider == kopis.GitHubProvider {
		var values []struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}
		if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
			return nil, err
		}
		repositories := make([]kopis.Repository, 0, len(values))
		for _, value := range values {
			repositories = append(repositories, kopis.Repository{Provider: p.provider, ID: value.FullName, URL: value.HTMLURL, Owner: true, Accessible: true, Public: !value.Private})
		}
		return repositories, nil
	}
	var values []struct {
		ID         int    `json:"id"`
		PathWith   string `json:"path_with_namespace"`
		WebURL     string `json:"web_url"`
		Visibility string `json:"visibility"`
	}
	if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
		return nil, err
	}
	repositories := make([]kopis.Repository, 0, len(values))
	for _, value := range values {
		repositories = append(repositories, kopis.Repository{Provider: p.provider, ID: value.PathWith, URL: value.WebURL, Member: true, Accessible: true, Public: value.Visibility == "public"})
	}
	return repositories, nil
}

func (p runtimeProvider) discoveryPath() string {
	if p.provider == kopis.GitHubProvider {
		return "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member"
	}
	return "/api/v4/projects?membership=true&owned=true&per_page=100"
}

func (p runtimeProvider) Search(ctx context.Context, token string, repository kopis.Repository, query string, artifact kopis.Artifact) kopis.SearchOutcome {
	if p.provider == kopis.GitHubProvider {
		result := p.github.SearchCatalog(ctx, query+" repo:"+repository.ID, artifact)
		return kopis.SearchOutcome{Candidates: result.Candidates, Complete: result.Coverage.Status == kopis.GitHubComplete, Denied: result.Coverage.Status == kopis.GitHubUnscanned && result.Coverage.AccessAmbiguous, Unavailable: result.Coverage.Status == kopis.GitHubPartial}
	}
	result := p.gitlab.SearchCatalog(ctx, query, artifact, kopis.GitLabScope{Project: repository.ID})
	return kopis.SearchOutcome{Candidates: result.Candidates, Complete: result.Coverage.Status == kopis.GitLabComplete, Denied: result.Coverage.Status == kopis.GitLabUnscanned && result.Coverage.AccessAmbiguous, Unavailable: result.Coverage.Status == kopis.GitLabPartial}
}

func main() { os.Exit(run()) }

func run() int {
	providerName := flag.String("provider", "", "provider: github or gitlab")
	baseURL := flag.String("base-url", "", "provider API base URL")
	tokenEnv := flag.String("token-env", "", "environment variable containing the runtime token")
	scope := flag.String("scope", "", "comma-separated repository IDs; omit for authorized default scope")
	format := flag.String("format", "terminal", "output format: terminal or jsonl")
	flag.Parse()
	if *providerName != kopis.GitHubProvider && *providerName != kopis.GitLabProvider {
		fmt.Fprintln(os.Stderr, "kopis: provider must be github or gitlab")
		return 1
	}
	envName := *tokenEnv
	if envName == "" {
		if *providerName == kopis.GitHubProvider {
			envName = "GITHUB_TOKEN"
		} else {
			envName = "GITLAB_TOKEN"
		}
	}
	token := os.Getenv(envName)
	if strings.TrimSpace(token) == "" {
		fmt.Fprintln(os.Stderr, "kopis: runtime provider token is required")
		return 1
	}
	apiURL := *baseURL
	if apiURL == "" {
		if *providerName == kopis.GitHubProvider {
			apiURL = "https://api.github.com"
		} else {
			apiURL = "https://gitlab.com"
		}
	}
	provider := runtimeProvider{provider: *providerName, token: token, baseURL: apiURL}
	var err error
	if *providerName == kopis.GitHubProvider {
		provider.github, err = kopis.NewGitHubClient(kopis.GitHubConfig{BaseURL: apiURL, Token: token})
	} else {
		provider.gitlab, err = kopis.NewGitLabClient(kopis.GitLabConfig{BaseURL: apiURL, Token: token})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kopis:", err)
		return 1
	}
	request := kopis.ScanRequest{Provider: *providerName, Token: token, Scanner: provider, Catalog: kopis.InitialCatalog()}
	if *scope != "" {
		for _, id := range strings.Split(*scope, ",") {
			if strings.TrimSpace(id) != "" {
				request.Scope.RepositoryIDs = append(request.Scope.RepositoryIDs, strings.TrimSpace(id))
			}
		}
		request.Scope.Kind = kopis.ScopeList
		if len(request.Scope.RepositoryIDs) == 1 {
			request.Scope.Kind = kopis.ScopeRepository
		}
	}
	result, err := kopis.Scan(context.Background(), request)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kopis:", err)
		return 1
	}
	if *format == "terminal" {
		err = kopis.WriteTerminal(os.Stdout, result)
	} else if *format == "jsonl" {
		err = kopis.WriteJSONL(os.Stdout, result)
	} else {
		fmt.Fprintln(os.Stderr, "kopis: format must be terminal or jsonl")
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kopis: output failed")
		return 1
	}
	return kopis.ExitCode(result)
}
