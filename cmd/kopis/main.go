package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

var newGitHubRuntimeClient = kopis.NewGitHubClient

func (p runtimeProvider) ResolveRepository(ctx context.Context, token, id string) (kopis.Repository, error) {
	path := "/repos/" + strings.TrimPrefix(strings.TrimSpace(id), "/")
	if p.provider == kopis.GitLabProvider {
		path = "/api/v4/projects/" + url.PathEscape(strings.TrimSpace(id))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.baseURL, "/")+path, nil)
	if err != nil {
		return kopis.Repository{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return kopis.Repository{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusForbidden {
		return kopis.Repository{Provider: p.provider, ID: id, Accessible: false}, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return kopis.Repository{}, errors.New("provider repository lookup failed")
	}
	if p.provider == kopis.GitHubProvider {
		var value struct {
			FullName string `json:"full_name"`
			HTMLURL  string `json:"html_url"`
			Private  bool   `json:"private"`
		}
		if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
			return kopis.Repository{}, err
		}
		return kopis.Repository{Provider: p.provider, ID: value.FullName, URL: value.HTMLURL, Accessible: true, Public: !value.Private}, nil
	}
	var value struct {
		PathWith string `json:"path_with_namespace"`
		WebURL   string `json:"web_url"`
		Public   string `json:"visibility"`
	}
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		return kopis.Repository{}, err
	}
	return kopis.Repository{Provider: p.provider, ID: value.PathWith, URL: value.WebURL, Accessible: true, Public: value.Public == "public"}, nil
}

func (p runtimeProvider) Discover(ctx context.Context, token string) ([]kopis.Repository, error) {
	next := strings.TrimRight(p.baseURL, "/") + p.discoveryPath()
	var repositories []kopis.Repository
	for next != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			response.Body.Close()
			return nil, errors.New("provider repository discovery failed")
		}
		if p.provider == kopis.GitHubProvider {
			var values []struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
				Private  bool   `json:"private"`
			}
			if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
				response.Body.Close()
				return nil, err
			}
			response.Body.Close()
			for _, value := range values {
				repositories = append(repositories, kopis.Repository{Provider: p.provider, ID: value.FullName, URL: value.HTMLURL, Owner: true, Accessible: true, Public: !value.Private})
			}
			next = discoveryNext(response.Header.Get("Link"))
			continue
		}
		var values []struct {
			ID         int    `json:"id"`
			PathWith   string `json:"path_with_namespace"`
			WebURL     string `json:"web_url"`
			Visibility string `json:"visibility"`
		}
		if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
			response.Body.Close()
			return nil, err
		}
		nextPage := response.Header.Get("X-Next-Page")
		response.Body.Close()
		for _, value := range values {
			repositories = append(repositories, kopis.Repository{Provider: p.provider, ID: value.PathWith, URL: value.WebURL, Member: true, Accessible: true, Public: value.Visibility == "public"})
		}
		if nextPage == "" {
			next = ""
		} else {
			nextURL, parseErr := url.Parse(next)
			if parseErr != nil {
				return nil, parseErr
			}
			values := nextURL.Query()
			values.Set("page", nextPage)
			nextURL.RawQuery = values.Encode()
			next = nextURL.String()
		}
	}
	return repositories, nil
}

func (p runtimeProvider) discoveryPath() string {
	if p.provider == kopis.GitHubProvider {
		return "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&page=1"
	}
	return "/api/v4/projects?membership=true&per_page=100&page=1"
}

func discoveryNext(link string) string {
	for _, part := range strings.Split(link, ",") {
		pieces := strings.SplitN(strings.TrimSpace(part), ";", 2)
		if len(pieces) == 2 && strings.Contains(pieces[1], `rel="next"`) {
			return strings.Trim(pieces[0], " <>")
		}
	}
	return ""
}

func (p runtimeProvider) Search(ctx context.Context, token string, repository kopis.Repository, query string, artifact kopis.Artifact) kopis.SearchOutcome {
	if p.provider == kopis.GitHubProvider {
		result := p.github.SearchCatalog(ctx, query+" repo:"+repository.ID, artifact)
		return kopis.SearchOutcome{Candidates: result.Candidates, Complete: result.Coverage.Status == kopis.GitHubComplete, Denied: result.Coverage.Status == kopis.GitHubUnscanned && result.Coverage.AccessAmbiguous, Unavailable: result.Coverage.Status == kopis.GitHubPartial}
	}
	result := p.gitlab.SearchCatalog(ctx, query, artifact, kopis.GitLabScope{Project: repository.ID})
	return kopis.SearchOutcome{Candidates: result.Candidates, Complete: result.Coverage.Status == kopis.GitLabComplete, Denied: result.Coverage.Status == kopis.GitLabUnscanned && result.Coverage.AccessAmbiguous, Unavailable: result.Coverage.Status == kopis.GitLabPartial}
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kopis", flag.ContinueOnError)
	flags.SetOutput(stderr)
	providerName := flags.String("provider", "", "provider: github or gitlab")
	baseURL := flags.String("base-url", "", "provider API base URL")
	tokenEnv := flags.String("token-env", "", "environment variable containing the runtime token")
	scope := flags.String("scope", "", "comma-separated repository IDs; omit for authorized default scope")
	scopeFile := flags.String("scope-file", "", "file containing one repository ID per line, or - for standard input")
	format := flags.String("format", "terminal", "output format: terminal or jsonl")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if *providerName != kopis.GitHubProvider && *providerName != kopis.GitLabProvider {
		fmt.Fprintln(stderr, "kopis: provider must be github or gitlab")
		return 1
	}
	if *scope != "" && *scopeFile != "" {
		fmt.Fprintln(stderr, "kopis: scope and scope-file are mutually exclusive")
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
		fmt.Fprintln(stderr, "kopis: runtime provider token is required")
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
		provider.github, err = newGitHubRuntimeClient(kopis.GitHubConfig{BaseURL: apiURL, Token: token})
	} else {
		provider.gitlab, err = kopis.NewGitLabClient(kopis.GitLabConfig{BaseURL: apiURL, Token: token})
	}
	if err != nil {
		fmt.Fprintln(stderr, "kopis:", err)
		return 1
	}
	request := kopis.ScanRequest{Provider: *providerName, Token: token, Scanner: provider, Catalog: kopis.InitialCatalog()}
	if *scope != "" {
		request.Scope = commaScope(*scope)
	} else if *scopeFile != "" {
		var reader io.Reader = stdin
		if *scopeFile != "-" {
			file, openErr := os.Open(*scopeFile)
			if openErr != nil {
				fmt.Fprintln(stderr, "kopis: scope file:", openErr)
				return 1
			}
			defer file.Close()
			reader = file
		}
		request.Scope, err = kopis.ParseScope(reader)
		if err != nil {
			fmt.Fprintln(stderr, "kopis: scope file:", err)
			return 1
		}
	}
	result, err := kopis.Scan(context.Background(), request)
	if err != nil {
		fmt.Fprintln(stderr, "kopis:", err)
		return 1
	}
	if *format == "terminal" {
		err = kopis.WriteTerminal(stdout, result)
	} else if *format == "jsonl" {
		err = kopis.WriteJSONL(stdout, result)
	} else {
		fmt.Fprintln(stderr, "kopis: format must be terminal or jsonl")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "kopis: output failed")
		return 1
	}
	return kopis.ExitCode(result)
}

func commaScope(value string) kopis.Scope {
	var ids []string
	for _, id := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			ids = append(ids, trimmed)
		}
	}
	kind := kopis.ScopeList
	if len(ids) == 1 {
		kind = kopis.ScopeRepository
	}
	return kopis.Scope{Kind: kind, RepositoryIDs: ids}
}
