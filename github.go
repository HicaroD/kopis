package kopis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	GitHubProvider      = "github"
	GitHubComplete      = "complete"
	GitHubPartial       = "partial"
	GitHubUnscanned     = "unscanned"
	githubPageSize      = 100
	githubResultCap     = 1000
	githubQueryLimit    = 256
	githubBooleanLimit  = 5
	githubFileSizeLimit = 384 * 1024
)

type GitHubConfig struct {
	BaseURL      string
	Token        string
	HTTPClient   *http.Client
	Concurrency  int
	MaxRetries   int
	RetryWait    time.Duration
	MaxRetryWait time.Duration
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) bool
}

type GitHubFailure struct {
	Status          int
	Kind            string
	Retryable       bool
	AccessAmbiguous bool
	Message         string
}

type GitHubCoverage struct {
	Status                       string
	Pages                        int
	Results                      int
	ResultCapReached             bool
	IncompleteResults            bool
	DefaultBranchOnly            bool
	FileSizeLimitBytes           int
	ArchivedRepositoriesExcluded bool
	LargeRepositoriesExcluded    bool
	Throttled                    bool
	AccessAmbiguous              bool
	Failures                     []GitHubFailure
}

type GitHubSearchResult struct {
	Candidates []Candidate
	Coverage   GitHubCoverage
	Failures   []GitHubFailure
}

type GitHubClient struct {
	baseURL      *url.URL
	token        string
	httpClient   *http.Client
	concurrency  int
	maxRetries   int
	retryWait    time.Duration
	maxRetryWait time.Duration
	searchLimit  *searchLimiter
}

type searchLimiter struct {
	mu     sync.Mutex
	starts []time.Time
	now    func() time.Time
	sleep  func(context.Context, time.Duration) bool
	limit  int
}

type githubSearchResponse struct {
	TotalCount        int                `json:"total_count"`
	IncompleteResults bool               `json:"incomplete_results"`
	Items             []githubSearchItem `json:"items"`
}

type githubSearchItem struct {
	Name       string           `json:"name"`
	Path       string           `json:"path"`
	SHA        string           `json:"sha"`
	URL        string           `json:"html_url"`
	Repository githubRepository `json:"repository"`
}

type githubRepository struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	Private  bool   `json:"private"`
}

type githubBlobResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func NewGitHubClient(config GitHubConfig) (*GitHubClient, error) {
	if strings.TrimSpace(config.Token) == "" {
		return nil, errors.New("github token is required")
	}
	base, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("invalid github base URL")
	}
	client := config.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	concurrency := config.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}
	maxRetries := config.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	retryWait := config.RetryWait
	if retryWait <= 0 {
		retryWait = 10 * time.Millisecond
	}
	maxRetryWait := config.MaxRetryWait
	if maxRetryWait <= 0 {
		maxRetryWait = time.Second
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	sleep := config.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, delay time.Duration) bool {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
				return true
			case <-ctx.Done():
				return false
			}
		}
	}
	limiter := &searchLimiter{now: now, sleep: sleep, limit: 10}
	return &GitHubClient{baseURL: base, token: config.Token, httpClient: client, concurrency: concurrency, maxRetries: maxRetries, retryWait: retryWait, maxRetryWait: maxRetryWait, searchLimit: limiter}, nil
}

func (c *GitHubClient) Search(ctx context.Context, query string) GitHubSearchResult {
	result := GitHubSearchResult{Coverage: GitHubCoverage{
		Status:                       GitHubComplete,
		DefaultBranchOnly:            true,
		FileSizeLimitBytes:           githubFileSizeLimit,
		ArchivedRepositoriesExcluded: true,
		LargeRepositoriesExcluded:    true,
	}}
	if err := validateGitHubQuery(query); err != nil {
		result.Coverage.Status = GitHubUnscanned
		result.Failures = []GitHubFailure{{Kind: "malformed_query", Message: err.Error()}}
		result.Coverage.Failures = result.Failures
		return result
	}
	if c == nil || c.baseURL == nil || c.token == "" {
		result.Coverage.Status = GitHubUnscanned
		result.Failures = []GitHubFailure{{Kind: "credentials", Message: "usable GitHub credentials are required"}}
		result.Coverage.Failures = result.Failures
		return result
	}

	var items []githubSearchItem
	seenPages := map[string]bool{}
	discoveryFailure := false
	next := c.searchURL(query, "")
	for next != "" && len(items) < githubResultCap {
		if seenPages[next] {
			break
		}
		seenPages[next] = true
		response, pageItems, pageNext, failure := c.searchPage(ctx, next)
		result.Coverage.Pages++
		if failure != nil {
			discoveryFailure = true
			result.Failures = append(result.Failures, *failure)
			result.Coverage.Status = GitHubPartial
			if failure.Status == http.StatusUnauthorized || failure.Kind == "malformed_query" || failure.AccessAmbiguous {
				result.Coverage.Status = GitHubUnscanned
			}
			result.Coverage.Throttled = failure.Kind == "throttled" || failure.Status == http.StatusTooManyRequests
			result.Coverage.AccessAmbiguous = failure.AccessAmbiguous
			break
		}
		items = append(items, pageItems...)
		if response.IncompleteResults {
			result.Coverage.IncompleteResults = true
			result.Coverage.Status = GitHubPartial
		}
		if response.TotalCount >= githubResultCap || len(items) >= githubResultCap {
			result.Coverage.ResultCapReached = true
			result.Coverage.Status = GitHubPartial
			break
		}
		next = pageNext
	}
	if len(items) >= githubResultCap {
		items = items[:githubResultCap]
	}
	result.Coverage.Results = len(items)
	discoveryFailureCount := len(result.Failures)
	result.Candidates, result.Failures = c.retrieveCandidates(ctx, items, result.Failures)
	result.Coverage.Failures = result.Failures
	if len(result.Failures) > discoveryFailureCount {
		result.Coverage.Status = GitHubPartial
	}
	for _, failure := range result.Failures {
		if failure.AccessAmbiguous {
			result.Coverage.AccessAmbiguous = true
		}
		if failure.Kind == "throttled" || failure.Status == http.StatusTooManyRequests {
			result.Coverage.Throttled = true
		}
		if (!failure.AccessAmbiguous || !discoveryFailure) && (failure.Kind == "transport" || failure.Kind == "unavailable" || failure.Retryable || failure.AccessAmbiguous) {
			result.Coverage.Status = GitHubPartial
		}
	}
	return result
}

func (c *GitHubClient) SearchCatalog(ctx context.Context, query string, artifact Artifact) GitHubSearchResult {
	result := c.Search(ctx, query)
	for i := range result.Candidates {
		result.Candidates[i].Tool = artifact.Rule.Tool
		result.Candidates[i].CatalogRule = artifact.Rule.ID
	}
	return result
}

func validateGitHubQuery(query string) error {
	if !utf8.ValidString(query) || githubSearchCharacters(query) > githubQueryLimit {
		return errors.New("GitHub search query exceeds 256 characters")
	}
	booleanOperators := 0
	for _, token := range strings.Fields(strings.ToLower(query)) {
		if token == "and" || token == "or" || token == "not" || strings.HasPrefix(token, "and:") || strings.HasPrefix(token, "or:") || strings.HasPrefix(token, "not:") {
			booleanOperators++
		}
	}
	if booleanOperators > githubBooleanLimit {
		return errors.New("GitHub search query exceeds five boolean operators")
	}
	return nil
}

func githubSearchCharacters(query string) int {
	qualifiers := []string{"repo:", "org:", "user:", "path:", "filename:", "extension:", "language:", "in:", "is:", "size:"}
	count := 0
	for _, token := range strings.Fields(query) {
		lower := strings.ToLower(token)
		documented := false
		for _, qualifier := range qualifiers {
			if strings.HasPrefix(lower, qualifier) {
				documented = true
				break
			}
		}
		if lower == "and" || lower == "or" || lower == "not" || documented {
			continue
		}
		count += utf8.RuneCountInString(token)
	}
	return count
}

func (l *searchLimiter) wait(ctx context.Context) bool {
	for {
		now := l.now()
		l.mu.Lock()
		cutoff := now.Add(-time.Minute)
		kept := l.starts[:0]
		for _, start := range l.starts {
			if start.After(cutoff) {
				kept = append(kept, start)
			}
		}
		l.starts = kept
		if len(l.starts) < l.limit {
			l.starts = append(l.starts, now)
			l.mu.Unlock()
			return true
		}
		delay := l.starts[0].Add(time.Minute).Sub(now)
		if delay < 0 {
			delay = 0
		}
		l.mu.Unlock()
		if !l.sleep(ctx, delay) {
			return false
		}
	}
}

func (c *GitHubClient) searchURL(query, page string) string {
	values := url.Values{"q": {query}, "per_page": {strconv.Itoa(githubPageSize)}}
	if page != "" {
		values.Set("page", page)
	}
	return c.endpoint("/search/code", values)
}

func (c *GitHubClient) searchPage(ctx context.Context, rawURL string) (githubSearchResponse, []githubSearchItem, string, *GitHubFailure) {
	request, err := c.request(ctx, rawURL)
	if err != nil {
		return githubSearchResponse{}, nil, "", &GitHubFailure{Kind: "request", Message: "could not create GitHub request"}
	}
	response, failure := c.do(request, c.searchLimit)
	if failure != nil {
		return githubSearchResponse{}, nil, "", failure
	}
	defer response.Body.Close()
	var search githubSearchResponse
	if err := json.NewDecoder(response.Body).Decode(&search); err != nil {
		return githubSearchResponse{}, nil, "", &GitHubFailure{Status: response.StatusCode, Kind: "invalid_response", Message: "GitHub returned an invalid search response"}
	}
	return search, search.Items, c.parseNextLink(response.Header.Get("Link")), nil
}

func (c *GitHubClient) retrieveCandidates(ctx context.Context, items []githubSearchItem, failures []GitHubFailure) ([]Candidate, []GitHubFailure) {
	type retrieved struct {
		candidate Candidate
		failure   *GitHubFailure
	}
	if len(items) == 0 {
		return nil, failures
	}
	jobs := make(chan githubSearchItem)
	results := make(chan retrieved, len(items))
	workers := c.concurrency
	if workers > len(items) {
		workers = len(items)
	}
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for item := range jobs {
				content, failure := c.retrieve(ctx, item)
				if failure != nil {
					results <- retrieved{failure: failure}
					continue
				}
				results <- retrieved{candidate: Candidate{Provider: GitHubProvider, Repository: item.Repository.FullName, RepositoryURL: item.Repository.HTMLURL, Revision: item.SHA, Path: item.Path, Content: content}}
			}
		}()
	}
	go func() {
		for _, item := range items {
			jobs <- item
		}
		close(jobs)
		wait.Wait()
		close(results)
	}()
	candidates := make([]Candidate, 0, len(items))
	for item := range results {
		if item.failure != nil {
			failures = append(failures, *item.failure)
		} else {
			candidates = append(candidates, item.candidate)
		}
	}
	return candidates, failures
}

func (c *GitHubClient) retrieve(ctx context.Context, item githubSearchItem) (string, *GitHubFailure) {
	parts := strings.SplitN(item.Repository.FullName, "/", 2)
	if len(parts) != 2 || item.SHA == "" {
		return "", &GitHubFailure{Kind: "incomplete_result", Message: "GitHub search result lacks pinned retrieval identity"}
	}
	rawURL := c.endpoint("/repos/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1])+"/git/blobs/"+url.PathEscape(item.SHA), nil)
	request, err := c.request(ctx, rawURL)
	if err != nil {
		return "", &GitHubFailure{Kind: "request", Message: "could not create GitHub retrieval request"}
	}
	response, failure := c.do(request, nil)
	if failure != nil {
		return "", failure
	}
	defer response.Body.Close()
	var blob githubBlobResponse
	if err := json.NewDecoder(response.Body).Decode(&blob); err != nil {
		return "", &GitHubFailure{Status: response.StatusCode, Kind: "invalid_response", Message: "GitHub returned an invalid blob response"}
	}
	if blob.Encoding != "base64" {
		return "", &GitHubFailure{Status: response.StatusCode, Kind: "invalid_response", Message: "GitHub blob was not base64 encoded"}
	}
	content, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(strings.Join(strings.Fields(blob.Content), ""))))
	if err != nil {
		return "", &GitHubFailure{Status: response.StatusCode, Kind: "invalid_response", Message: "GitHub blob content was invalid"}
	}
	return string(content), nil
}

func (c *GitHubClient) request(ctx context.Context, rawURL string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/vnd.github+json")
	return request, nil
}

func (c *GitHubClient) endpoint(path string, query url.Values) string {
	requestURL := *c.baseURL
	requestURL.Path = strings.TrimRight(requestURL.Path, "/") + path
	requestURL.RawQuery = ""
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}
	return requestURL.String()
}

func (c *GitHubClient) do(request *http.Request, searchBudget *searchLimiter) (*http.Response, *GitHubFailure) {
	for attempt := 0; ; attempt++ {
		if searchBudget != nil && !searchBudget.wait(request.Context()) {
			return nil, &GitHubFailure{Kind: "throttled", Retryable: true, Message: "GitHub code-search budget wait was canceled"}
		}
		response, err := c.httpClient.Do(request)
		if err != nil {
			if attempt >= c.maxRetries || request.Context().Err() != nil {
				return nil, &GitHubFailure{Kind: "transport", Retryable: attempt < c.maxRetries, Message: "GitHub request failed"}
			}
			if !c.wait(request.Context(), attempt, 0) {
				return nil, &GitHubFailure{Kind: "transport", Retryable: true, Message: "GitHub retry was canceled"}
			}
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}
		rateLimited := response.StatusCode == http.StatusTooManyRequests || (response.StatusCode == http.StatusForbidden && (response.Header.Get("Retry-After") != "" || response.Header.Get("X-RateLimit-Remaining") == "0"))
		retryable := response.StatusCode == http.StatusServiceUnavailable || rateLimited
		if !retryable || attempt >= c.maxRetries {
			failure := githubFailureForStatus(response.StatusCode, rateLimited)
			response.Body.Close()
			return nil, &failure
		}
		delay := githubRetryAfter(response.Header.Get("Retry-After"))
		if delay <= 0 {
			delay = resetDelay(response.Header.Get("X-RateLimit-Reset"))
		}
		response.Body.Close()
		if !c.wait(request.Context(), attempt, delay) {
			return nil, &GitHubFailure{Status: response.StatusCode, Kind: "throttled", Retryable: true, Message: "GitHub retry was canceled"}
		}
	}
}

func (c *GitHubClient) wait(ctx context.Context, attempt int, requested time.Duration) bool {
	delay := requested
	if delay <= 0 {
		delay = c.retryWait * time.Duration(1<<min(attempt, 6))
	}
	if delay > c.maxRetryWait {
		delay = c.maxRetryWait
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func githubFailureForStatus(status int, rateLimited bool) GitHubFailure {
	failure := GitHubFailure{Status: status, Kind: "provider", Message: fmt.Sprintf("GitHub request returned status %d", status)}
	switch {
	case status == http.StatusUnauthorized:
		failure.Kind, failure.Message = "credentials", "GitHub credentials were rejected"
	case status == http.StatusNotFound:
		failure.Kind, failure.Message, failure.AccessAmbiguous = "not_found", "GitHub resource was not found or is inaccessible", true
	case status == http.StatusUnprocessableEntity:
		failure.Kind, failure.Message = "malformed_request", "GitHub rejected the search request"
	case rateLimited || status == http.StatusTooManyRequests:
		failure.Kind, failure.Message, failure.Retryable = "throttled", "GitHub rate limit was reached", true
	case status == http.StatusServiceUnavailable:
		failure.Kind, failure.Message, failure.Retryable = "unavailable", "GitHub search is unavailable", true
	}
	return failure
}

func (c *GitHubClient) parseNextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		pieces := strings.SplitN(strings.TrimSpace(part), ";", 2)
		if len(pieces) == 2 && strings.Contains(pieces[1], `rel="next"`) {
			return strings.Trim(pieces[0], " <>")
		}
	}
	return ""
}

func githubRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func resetDelay(value string) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	delay := time.Until(time.Unix(seconds, 0))
	if delay < 0 {
		return 0
	}
	return delay
}
