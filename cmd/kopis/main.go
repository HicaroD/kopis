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
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	kopis "github.com/HicaroD/kopis"
)

type runtimeProvider struct {
	provider   string
	token      string
	baseURL    string
	httpClient *http.Client
	github     *kopis.GitHubClient
	gitlab     *kopis.GitLabClient
}

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
	response, err := p.http().Do(request)
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
		response, err := p.http().Do(request)
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

func (p runtimeProvider) ListFiles(ctx context.Context, _ string, repository kopis.Repository) kopis.FileListing {
	if p.provider == kopis.GitHubProvider {
		return p.github.ListFiles(ctx, repository.ID)
	}
	return p.gitlab.ListFiles(ctx, repository.ID)
}

func (p runtimeProvider) FetchFile(ctx context.Context, _ string, repository kopis.Repository, file kopis.RepositoryFile) kopis.FileOutcome {
	if p.provider == kopis.GitHubProvider {
		return p.github.FetchFile(ctx, repository.ID, file)
	}
	return p.gitlab.FetchFile(ctx, repository.ID, file)
}

func (p runtimeProvider) http() *http.Client {
	if p.httpClient != nil {
		return p.httpClient
	}
	return http.DefaultClient
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	status := runContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdin, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kopis", flag.ContinueOnError)
	flags.SetOutput(stderr)
	providerName := flags.String("provider", "", "provider: github or gitlab")
	baseURL := flags.String("base-url", "", "provider API base URL")
	tokenEnv := flags.String("token-env", "", "environment variable containing the runtime token")
	scope := flags.String("scope", "", "comma-separated repository IDs; omit for authorized default scope")
	scopeFile := flags.String("scope-file", "", "file containing one repository ID per line, or - for standard input")
	format := flags.String("format", "terminal", "output format: terminal or jsonl")
	outputPath := flags.String("o", "", "write the report to this file (overwrites an existing report)")
	explain := flags.Bool("explain", false, "report catalog path handoffs on standard error without file content")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if *format != "terminal" && *format != "jsonl" {
		fmt.Fprintln(stderr, "kopis: format must be terminal or jsonl")
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
	client := &http.Client{Timeout: 30 * time.Second}
	provider := runtimeProvider{provider: *providerName, token: token, baseURL: apiURL, httpClient: client}
	var err error
	if *providerName == kopis.GitHubProvider {
		provider.github, err = kopis.NewGitHubClient(kopis.GitHubConfig{BaseURL: apiURL, Token: token, HTTPClient: client})
	} else {
		provider.gitlab, err = kopis.NewGitLabClient(kopis.GitLabConfig{BaseURL: apiURL, Token: token, HTTPClient: client})
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
	request.Progress = func(completed, total int) {
		fmt.Fprintf(stderr, "kopis: repositories %d/%d complete\n", completed, total)
	}
	fmt.Fprintln(stderr, "kopis: preparing repository scope...")
	result, err := kopis.Scan(ctx, request)
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "kopis: scan canceled")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "kopis:", err)
		return 1
	}
	if *explain {
		for _, repository := range result.Repositories {
			d := repository.Diagnostics
			fmt.Fprintf(stderr, "kopis: repository=%q status=%s listed=%d listing_complete=%t matched=%d fetched=%d inspected=%d failed=%d\n", repository.Repository.ID, repository.Status, d.ListedFiles, d.ListingComplete, len(d.MatchedPaths), len(d.FetchedPaths), len(d.InspectedPaths), len(d.FailedPaths))
			for _, stage := range []struct {
				name  string
				paths []string
			}{
				{"matched", d.MatchedPaths}, {"fetched", d.FetchedPaths}, {"inspected", d.InspectedPaths}, {"failed", d.FailedPaths},
			} {
				for _, path := range stage.paths {
					fmt.Fprintf(stderr, "kopis: repository=%q path=%q stage=%s\n", repository.Repository.ID, path, stage.name)
				}
			}
		}
	}
	if *outputPath == "" {
		err = writeReport(stdout, *format, result)
	} else {
		err = writeReportFile(*outputPath, *format, result)
	}
	if err != nil {
		fmt.Fprintln(stderr, "kopis: output failed")
		return 1
	}
	return kopis.ExitCode(result)
}

func writeReport(w io.Writer, format string, result kopis.ScanResult) error {
	if format == "jsonl" {
		return kopis.WriteJSONL(w, result)
	}
	return kopis.WriteTerminal(w, result)
}

func writeReportFile(path, format string, result kopis.ScanResult) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".kopis-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := writeReport(file, format, result); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
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
