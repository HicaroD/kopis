package kopis

import (
	"context"
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
)

const (
	GitLabProvider   = "gitlab"
	GitLabComplete   = "complete"
	GitLabPartial    = "partial"
	GitLabUnscanned  = "unscanned"
	gitLabPageSize   = 100
	gitLabResultCap  = 10000
	gitLabIndexLimit = 1 << 20
)

// GitLabScope identifies the project or group search endpoint. IDs may be
// numeric IDs or URL-encoded namespace paths.
type GitLabScope struct {
	Project string
	Group   string
}

// GitLabConfig controls an authenticated GitLab API client. BaseURL is the
// instance root, for example https://gitlab.com.
type GitLabConfig struct {
	BaseURL      string
	Token        string
	HTTPClient   *http.Client
	Concurrency  int
	MaxRetries   int
	RetryWait    time.Duration
	MaxRetryWait time.Duration
	Now          func() time.Time
	Sleep        func(context.Context, time.Duration) bool
	Capabilities *GitLabCapabilities
}

// GitLabCapabilities describes instance features that affect blob discovery.
type GitLabCapabilities struct {
	AdvancedSearch  bool
	ExactCodeSearch bool
	GlobalSearch    bool
	SearchAvailable bool
	IndexLimitBytes int
	ResultLimit     int
	SelfManaged     bool
}

// GitLabFailure retains a safe provider outcome without response bodies or
// credentials.
type GitLabFailure struct {
	Status          int
	Kind            string
	Retryable       bool
	AccessAmbiguous bool
	Message         string
}

// GitLabCoverage is the provider-native completeness signal for one search.
type GitLabCoverage struct {
	Status            string
	Pages             int
	Results           int
	ResultCapReached  bool
	IndexBoundary     bool
	SearchUnavailable bool
	Throttled         bool
	AccessAmbiguous   bool
	Failures          []GitLabFailure
}

// GitLabBlob is a catalog search result. GitLab returns an excerpt in Data;
// callers must use the adapter's Candidate results for complete content.
type GitLabBlob struct {
	ProjectID     string `json:"project_id"`
	ProjectPath   string `json:"project_path"`
	ProjectWebURL string `json:"project_web_url"`
	Path          string `json:"path"`
	Ref           string `json:"ref"`
	BlobID        string `json:"blob_id"`
	Data          string `json:"data"`
	Size          int64  `json:"size"`
}

// GitLabSearchResult contains candidates and the coverage signal for one
// project or group request.
type GitLabSearchResult struct {
	Candidates []Candidate
	Coverage   GitLabCoverage
	Failures   []GitLabFailure
}

// GitLabClient searches catalog-derived terms and retrieves pinned file bytes.
type GitLabClient struct {
	baseURL      *url.URL
	token        string
	httpClient   *http.Client
	concurrency  int
	maxRetries   int
	retryWait    time.Duration
	maxRetryWait time.Duration
	searchLimit  *searchLimiter
	capabilities *GitLabCapabilities
}

// NewGitLabClient creates an authenticated client without making a request.
func NewGitLabClient(config GitLabConfig) (*GitLabClient, error) {
	if strings.TrimSpace(config.Token) == "" {
		return nil, errors.New("gitlab token is required")
	}
	base, err := url.Parse(strings.TrimRight(config.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("invalid gitlab base URL")
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
	limiter := &searchLimiter{now: now, sleep: sleep, limit: 100}
	return &GitLabClient{baseURL: base, token: config.Token, httpClient: client, concurrency: concurrency, maxRetries: maxRetries, retryWait: retryWait, maxRetryWait: maxRetryWait, searchLimit: limiter, capabilities: config.Capabilities}, nil
}

// Capabilities reports the portable GitLab search boundary. GitLab.com does
// not expose a global code-search endpoint; callers must supply a project or
// group scope there.
func (c *GitLabClient) Capabilities(ctx context.Context) (GitLabCapabilities, *GitLabFailure) {
	if c == nil || c.baseURL == nil {
		return GitLabCapabilities{}, &GitLabFailure{Kind: "unavailable", Message: "GitLab instance is unavailable"}
	}
	if c.capabilities != nil {
		return *c.capabilities, nil
	}
	result := GitLabCapabilities{IndexLimitBytes: gitLabIndexLimit, ResultLimit: gitLabResultCap}
	if strings.EqualFold(c.baseURL.Hostname(), "gitlab.com") {
		result.AdvancedSearch = true
		result.ExactCodeSearch = true
		result.SearchAvailable = true
		result.GlobalSearch = false
	} else {
		result.GlobalSearch = false
		result.SelfManaged = true
	}
	return result, nil
}

// SearchProject searches project blobs and retrieves each distinct file at its
// result ref. Search terms must be derived from the approved catalog.
func (c *GitLabClient) SearchProject(ctx context.Context, search string, project string) GitLabSearchResult {
	return c.search(ctx, search, GitLabScope{Project: project})
}

// SearchCatalog searches for one admitted catalog rule and preserves its
// identity on every candidate handed to inspection.
func (c *GitLabClient) SearchCatalog(ctx context.Context, search string, artifact Artifact, scope GitLabScope) GitLabSearchResult {
	result := c.search(ctx, search, scope)
	for i := range result.Candidates {
		result.Candidates[i].Tool = artifact.Rule.Tool
		result.Candidates[i].CatalogRule = artifact.Rule.ID
	}
	return result
}

// SearchGroup searches group blobs and retrieves each distinct file at its
// result ref.
func (c *GitLabClient) SearchGroup(ctx context.Context, search string, group string) GitLabSearchResult {
	return c.search(ctx, search, GitLabScope{Group: group})
}

// Search is the scope-aware entry point for project or group discovery.
func (c *GitLabClient) Search(ctx context.Context, search string, scope GitLabScope) GitLabSearchResult {
	return c.search(ctx, search, scope)
}

func (c *GitLabClient) search(ctx context.Context, search string, scope GitLabScope) GitLabSearchResult {
	result := GitLabSearchResult{Coverage: GitLabCoverage{Status: GitLabComplete}}
	if strings.TrimSpace(search) == "" || (scope.Project == "" && scope.Group == "") || (scope.Project != "" && scope.Group != "") {
		result.Coverage.Status = GitLabUnscanned
		result.Failures = append(result.Failures, GitLabFailure{Kind: "invalid_scope", Message: "search and exactly one scope are required"})
		result.Coverage.Failures = result.Failures
		return result
	}
	if c == nil || c.baseURL == nil || c.token == "" {
		result.Coverage.Status = GitLabUnscanned
		result.Failures = append(result.Failures, GitLabFailure{Kind: "credentials", Message: "usable GitLab credentials are required"})
		result.Coverage.Failures = result.Failures
		return result
	}

	var blobs []GitLabBlob
	truncated := false
	continuedAtCap := false
	for page := 1; len(blobs) < gitLabResultCap; page++ {
		pageBlobs, next, failure := c.searchPage(ctx, search, scope, page)
		result.Coverage.Pages++
		remaining := gitLabResultCap - len(blobs)
		if len(pageBlobs) > remaining {
			pageBlobs = pageBlobs[:remaining]
			truncated = true
		}
		blobs = append(blobs, pageBlobs...)
		if failure != nil {
			result.Failures = append(result.Failures, *failure)
			result.Coverage.Failures = result.Failures
			result.Coverage.Status = GitLabPartial
			if failure.Status == http.StatusUnauthorized || failure.AccessAmbiguous {
				result.Coverage.Status = GitLabUnscanned
			}
			result.Coverage.Throttled = failure.Status == http.StatusTooManyRequests || failure.Kind == "throttled"
			result.Coverage.SearchUnavailable = failure.Status == http.StatusNotImplemented || failure.Status == http.StatusServiceUnavailable
			result.Coverage.AccessAmbiguous = failure.AccessAmbiguous
			break
		}
		if !next {
			break
		}
		if len(blobs) >= gitLabResultCap {
			continuedAtCap = true
			break
		}
	}
	if (continuedAtCap || truncated) && len(blobs) >= gitLabResultCap {
		result.Coverage.ResultCapReached = true
		result.Coverage.Status = GitLabPartial
	}
	result.Coverage.Results = len(blobs)

	unique := make(map[string]GitLabBlob)
	for _, blob := range blobs {
		if blob.Size > gitLabIndexLimit {
			result.Coverage.IndexBoundary = true
			result.Coverage.Status = GitLabPartial
			continue
		}
		key := blob.ProjectID + "\x00" + blob.ProjectPath + "\x00" + blob.Path
		if _, exists := unique[key]; !exists {
			unique[key] = blob
		}
	}

	items := make([]GitLabBlob, 0, len(unique))
	for _, blob := range unique {
		items = append(items, blob)
	}
	candidates, failures := c.retrieveCandidates(ctx, items)
	result.Candidates = candidates
	result.Failures = append(result.Failures, failures...)
	result.Coverage.Failures = result.Failures
	if len(failures) > 0 {
		result.Coverage.Status = GitLabPartial
		for _, failure := range failures {
			if failure.AccessAmbiguous {
				result.Coverage.AccessAmbiguous = true
			}
		}
	}
	return result
}

func (c *GitLabClient) searchPage(ctx context.Context, search string, scope GitLabScope, page int) ([]GitLabBlob, bool, *GitLabFailure) {
	endpoint := "/api/v4/projects/" + escapePathValue(scope.Project) + "/search"
	if scope.Group != "" {
		endpoint = "/api/v4/groups/" + escapePathValue(scope.Group) + "/search"
	}
	query := url.Values{"scope": {"blobs"}, "search": {search}, "per_page": {strconv.Itoa(gitLabPageSize)}, "page": {strconv.Itoa(page)}}
	request, err := c.newRequest(ctx, endpoint, query)
	if err != nil {
		failure := GitLabFailure{Kind: "request", Message: "could not create GitLab request"}
		return nil, false, &failure
	}
	response, failure := c.do(request, c.searchLimit)
	if failure != nil {
		return nil, false, failure
	}
	defer response.Body.Close()
	var blobs []GitLabBlob
	if err := json.NewDecoder(response.Body).Decode(&blobs); err != nil {
		failure := GitLabFailure{Status: response.StatusCode, Kind: "invalid_response", Message: "GitLab returned an invalid search response"}
		return nil, false, &failure
	}
	next := response.Header.Get("X-Next-Page") != ""
	if link := response.Header.Get("Link"); link != "" && strings.Contains(link, `rel="next"`) {
		next = true
	}
	return blobs, next, nil
}

func (c *GitLabClient) retrieveCandidates(ctx context.Context, blobs []GitLabBlob) ([]Candidate, []GitLabFailure) {
	type retrieved struct {
		candidate Candidate
		failure   *GitLabFailure
	}
	jobs := make(chan GitLabBlob)
	results := make(chan retrieved, len(blobs))
	workers := c.concurrency
	if workers > len(blobs) {
		workers = len(blobs)
	}
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for blob := range jobs {
				content, failure := c.retrieve(ctx, blob)
				if failure != nil {
					results <- retrieved{failure: failure}
					continue
				}
				results <- retrieved{candidate: Candidate{Provider: GitLabProvider, Repository: firstNonEmpty(blob.ProjectPath, blob.ProjectID), RepositoryURL: blob.ProjectWebURL, Revision: blob.Ref, Path: blob.Path, Content: content}}
			}
		}()
	}
	go func() {
		for _, blob := range blobs {
			jobs <- blob
		}
		close(jobs)
		wait.Wait()
		close(results)
	}()
	var candidates []Candidate
	var failures []GitLabFailure
	for item := range results {
		if item.failure != nil {
			failures = append(failures, *item.failure)
		} else {
			candidates = append(candidates, item.candidate)
		}
	}
	return candidates, failures
}

func (c *GitLabClient) retrieve(ctx context.Context, blob GitLabBlob) (string, *GitLabFailure) {
	if blob.ProjectID == "" || blob.Path == "" || blob.Ref == "" {
		return "", &GitLabFailure{Kind: "incomplete_result", Message: "GitLab search result lacks pinned retrieval identity"}
	}
	endpoint := "/api/v4/projects/" + escapePathValue(blob.ProjectID) + "/repository/files/" + escapePathValue(blob.Path) + "/raw"
	query := url.Values{"ref": {blob.Ref}}
	request, err := c.newRequest(ctx, endpoint, query)
	if err != nil {
		return "", &GitLabFailure{Kind: "request", Message: "could not create GitLab request"}
	}
	response, failure := c.do(request, nil)
	if failure != nil {
		return "", failure
	}
	defer response.Body.Close()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return "", &GitLabFailure{Status: response.StatusCode, Kind: "read", Message: "could not read GitLab artifact"}
	}
	return string(content), nil
}

func (c *GitLabClient) newRequest(ctx context.Context, endpoint string, query url.Values) (*http.Request, error) {
	requestURL := *c.baseURL
	escapedPath := strings.TrimRight(requestURL.EscapedPath(), "/") + endpoint
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, err
	}
	requestURL.Path = decodedPath
	requestURL.RawPath = escapedPath
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	return request, nil
}

func (c *GitLabClient) do(request *http.Request, searchBudget *searchLimiter) (*http.Response, *GitLabFailure) {
	for attempt := 0; ; attempt++ {
		if searchBudget != nil && !searchBudget.wait(request.Context()) {
			return nil, &GitLabFailure{Kind: "throttled", Retryable: true, Message: "GitLab search budget wait was canceled"}
		}
		response, err := c.httpClient.Do(request)
		if err != nil {
			if attempt >= c.maxRetries || request.Context().Err() != nil {
				return nil, &GitLabFailure{Kind: "transport", Retryable: attempt < c.maxRetries, Message: "GitLab request failed"}
			}
			if !c.wait(request.Context(), attempt, 0) {
				return nil, &GitLabFailure{Kind: "transport", Retryable: true, Message: "GitLab request was canceled"}
			}
			continue
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return response, nil
		}
		retryable := response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusInternalServerError || response.StatusCode == http.StatusBadGateway || response.StatusCode == http.StatusServiceUnavailable || response.StatusCode == http.StatusGatewayTimeout
		if !retryable || attempt >= c.maxRetries {
			failure := failureForStatus(response.StatusCode)
			response.Body.Close()
			return nil, &failure
		}
		delay := retryAfter(response.Header.Get("Retry-After"))
		response.Body.Close()
		if !c.wait(request.Context(), attempt, delay) {
			return nil, &GitLabFailure{Status: response.StatusCode, Kind: "throttled", Retryable: true, Message: "GitLab retry was canceled"}
		}
	}
}

func (c *GitLabClient) wait(ctx context.Context, attempt int, requested time.Duration) bool {
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

func retryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func failureForStatus(status int) GitLabFailure {
	failure := GitLabFailure{Status: status, Kind: "provider", Message: fmt.Sprintf("GitLab request returned status %d", status)}
	switch status {
	case http.StatusUnauthorized:
		failure.Kind, failure.Message = "credentials", "GitLab credentials were rejected"
	case http.StatusBadRequest:
		failure.Kind, failure.Message = "malformed_request", "GitLab rejected the search request"
	case http.StatusNotFound:
		failure.Kind, failure.Message, failure.AccessAmbiguous = "not_found", "GitLab resource was not found or is inaccessible", true
	case http.StatusNotImplemented, http.StatusServiceUnavailable:
		failure.Kind, failure.Message, failure.Retryable = "unavailable", "GitLab search is unavailable", true
	case http.StatusTooManyRequests:
		failure.Kind, failure.Message, failure.Retryable = "throttled", "GitLab rate limit was reached", true
	}
	return failure
}

func escapePathValue(value string) string { return url.PathEscape(value) }
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
