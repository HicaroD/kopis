package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	kopis "github.com/HicaroD/kopis"
)

const checkpointVersion = 1
const maxCrawlAttempts = 3
const inspectionVersion = "format-aware-v4"

type crawlItem struct {
	ID         int64            `json:"id"`
	Repository kopis.Repository `json:"repository"`
	Attempts   int              `json:"attempts"`
}

type crawlCheckpoint struct {
	Version         int                      `json:"version"`
	Provider        string                   `json:"provider"`
	Instance        string                   `json:"instance"`
	Catalog         string                   `json:"catalog"`
	LastID          int64                    `json:"last_id"`
	EndID           int64                    `json:"end_id,omitempty"`
	EnumerationDone bool                     `json:"enumeration_done"`
	Scanned         int64                    `json:"scanned"`
	Pending         []crawlItem              `json:"pending,omitempty"`
	Retry           []crawlItem              `json:"retry,omitempty"`
	Gaps            []crawlItem              `json:"gaps,omitempty"`
	Undelivered     []kopis.RepositoryResult `json:"undelivered,omitempty"`
	Findings        []kopis.Finding          `json:"findings,omitempty"`
}

func defaultCheckpointPath(provider, instance string) string {
	sum := sha256.Sum256([]byte(crawlInstance(instance)))
	return fmt.Sprintf(".kopis-crawl-%s-%x.json", provider, sum[:6])
}

func crawlInstance(raw string) string {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func catalogIdentity(catalog []kopis.Artifact) string {
	encoded, _ := json.Marshal(catalog)
	sum := sha256.Sum256(append([]byte(inspectionVersion+":"), encoded...))
	return fmt.Sprintf("%x", sum)
}

func loadCrawl(path, provider, instance, catalog string) (crawlCheckpoint, error) {
	state := crawlCheckpoint{Version: checkpointVersion, Provider: provider, Instance: instance, Catalog: catalog}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, fmt.Errorf("invalid crawl checkpoint: %w", err)
	}
	if state.Version != checkpointVersion || state.Provider != provider || state.Instance != instance || state.Catalog != catalog || state.LastID < 0 || state.EndID < 0 {
		return state, errors.New("crawl checkpoint does not match provider, instance, or catalog")
	}
	return state, nil
}

func saveCrawl(path string, state crawlCheckpoint) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".kopis-checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(state); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// Acknowledge only after the whole report has been written. Replaying a report
// after a crash between write and acknowledgement is safer than losing findings.
func acknowledgeCrawl(path, provider, instance, catalog string) error {
	state, err := loadCrawl(path, provider, crawlInstance(instance), catalog)
	if err != nil {
		return err
	}
	state.Undelivered = nil
	state.Findings = nil
	return saveCrawl(path, state)
}

func addCrawlResult(repositories []kopis.RepositoryResult, findings []kopis.Finding, batch kopis.ScanResult) ([]kopis.RepositoryResult, []kopis.Finding) {
	for _, repository := range batch.Repositories {
		replaced := false
		for i := range repositories {
			if repositories[i].Repository.Provider == repository.Repository.Provider && repositories[i].Repository.ID == repository.Repository.ID {
				repositories[i] = repository
				replaced = true
				break
			}
		}
		if !replaced {
			repositories = append(repositories, repository)
		}
		kept := findings[:0]
		for _, finding := range findings {
			if finding.Provider != repository.Repository.Provider || finding.Repository != repository.Repository.ID {
				kept = append(kept, finding)
			}
		}
		findings = kept
	}
	return repositories, append(findings, batch.Findings...)
}

func (p runtimeProvider) publicPage(ctx context.Context, token string, since int64, upper int64) ([]crawlItem, bool, error) {
	root := strings.TrimRight(p.baseURL, "/")
	path := "/repositories"
	query := url.Values{}
	if p.provider == kopis.GitHubProvider {
		query.Set("per_page", "100")
		if since != 0 {
			query.Set("since", strconv.FormatInt(since, 10))
		}
	} else {
		path = "/api/v4/projects"
		query.Set("visibility", "public")
		query.Set("pagination", "keyset")
		query.Set("order_by", "id")
		query.Set("sort", "asc")
		query.Set("per_page", "100")
		if since != 0 {
			query.Set("id_after", strconv.FormatInt(since, 10))
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, root+path+"?"+query.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := p.http().Do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, false, fmt.Errorf("public discovery returned status %d", response.StatusCode)
	}
	var values []struct {
		ID         int64  `json:"id"`
		FullName   string `json:"full_name"`
		HTMLURL    string `json:"html_url"`
		Private    bool   `json:"private"`
		PathWith   string `json:"path_with_namespace"`
		WebURL     string `json:"web_url"`
		Visibility string `json:"visibility"`
	}
	if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
		return nil, false, errors.New("invalid public discovery response")
	}
	var items []crawlItem
	previous := since
	for _, value := range values {
		if value.ID <= previous {
			return nil, false, errors.New("public discovery IDs did not advance")
		}
		previous = value.ID
		if upper != 0 && value.ID > upper {
			return items, true, nil
		}
		repository := kopis.Repository{Provider: p.provider, Public: true, Accessible: true}
		if p.provider == kopis.GitHubProvider {
			if value.Private {
				return nil, false, errors.New("public discovery returned a private repository")
			}
			repository.ID, repository.URL = value.FullName, crawlInstance(value.HTMLURL)
		} else {
			if value.Visibility != "public" {
				return nil, false, errors.New("public discovery returned a non-public project")
			}
			repository.ID, repository.URL = value.PathWith, crawlInstance(value.WebURL)
		}
		if repository.ID == "" {
			return nil, false, errors.New("public discovery returned an invalid repository")
		}
		items = append(items, crawlItem{ID: value.ID, Repository: repository})
	}
	next := discoveryNext(response.Header.Get("Link"))
	if next != "" {
		parsed, parseErr := url.Parse(next)
		if parseErr != nil || parsed.Host != request.URL.Host || parsed.Scheme != request.URL.Scheme || parsed.Path != request.URL.Path {
			return nil, false, errors.New("invalid public discovery next link")
		}
	}
	return items, next == "", nil
}

func (p runtimeProvider) publicUpperID(ctx context.Context, token string) (int64, error) {
	query := url.Values{"visibility": {"public"}, "pagination": {"keyset"}, "order_by": {"id"}, "sort": {"desc"}, "per_page": {"1"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.baseURL, "/")+"/api/v4/projects?"+query.Encode(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := p.http().Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("public project boundary returned status %d", response.StatusCode)
	}
	var values []struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&values); err != nil {
		return 0, errors.New("invalid public project boundary")
	}
	if len(values) == 0 {
		return 0, nil
	}
	return values[0].ID, nil
}

func crawlPublic(ctx context.Context, request kopis.ScanRequest, provider runtimeProvider, path string, batchSize int, newPass bool) (kopis.ScanResult, error) {
	instance := crawlInstance(provider.baseURL)
	state, err := loadCrawl(path, request.Provider, instance, catalogIdentity(request.Catalog))
	if err != nil {
		return kopis.ScanResult{}, err
	}
	if batchSize < 1 {
		return kopis.ScanResult{}, errors.New("batch size must be positive")
	}
	if newPass {
		if !state.EnumerationDone || len(state.Pending) != 0 || len(state.Retry) != 0 || len(state.Gaps) != 0 || len(state.Undelivered) != 0 || len(state.Findings) != 0 {
			return kopis.ScanResult{}, errors.New("finish the current public pass before starting another")
		}
		state.LastID = state.EndID
		state.EndID = 0
		state.EnumerationDone = false
		state.Scanned = 0
		if err := saveCrawl(path, state); err != nil {
			return kopis.ScanResult{}, err
		}
	}
	result := kopis.ScanResult{Repositories: append([]kopis.RepositoryResult(nil), state.Undelivered...), Findings: append([]kopis.Finding(nil), state.Findings...)}
	if request.Provider == kopis.GitLabProvider && !state.EnumerationDone && state.EndID == 0 {
		upper, err := provider.publicUpperID(ctx, request.Token)
		if err != nil {
			return result, errors.New("public project boundary request failed")
		}
		state.EndID = upper
		state.EnumerationDone = upper <= state.LastID
		if err := saveCrawl(path, state); err != nil {
			return result, err
		}
	}
	retriesAvailable := len(state.Retry)
	discoveryFailure := ""
	progress := request.Progress
	if progress != nil {
		progress(0, batchSize)
	}
	for processed := 0; processed < batchSize && ctx.Err() == nil; {
		if !state.EnumerationDone && state.EndID > 0 && state.LastID >= state.EndID && len(state.Pending) == 0 {
			state.EnumerationDone = true
			if err := saveCrawl(path, state); err != nil {
				return result, err
			}
		}
		if len(state.Pending) == 0 && !state.EnumerationDone {
			items, done, err := provider.publicPage(ctx, request.Token, state.LastID, state.EndID)
			if err != nil {
				discoveryFailure = "public repository discovery failed"
				break // Preserve the committed cursor and return an incomplete report.
			}
			if len(items) == 0 && !done {
				discoveryFailure = "public repository discovery did not advance"
				break
			}
			state.Pending = items
			state.EnumerationDone = done
			if done && request.Provider == kopis.GitHubProvider {
				state.EndID = state.LastID
				if len(items) > 0 {
					state.EndID = items[len(items)-1].ID
				}
			}
			if err := saveCrawl(path, state); err != nil {
				return result, err
			}
		}
		var item crawlItem
		fresh := len(state.Pending) > 0
		if fresh {
			item = state.Pending[0]
		} else if retriesAvailable > 0 && len(state.Retry) > 0 {
			item = state.Retry[0]
		} else {
			break
		}
		request.Repositories = []kopis.Repository{item.Repository}
		request.Scope = kopis.Scope{Kind: kopis.ScopePublic}
		request.Progress = nil
		batch, err := kopis.Scan(ctx, request)
		if err != nil {
			return result, err
		}
		if ctx.Err() != nil {
			break // Leave this item pending for the next run.
		}
		result.Repositories, result.Findings = addCrawlResult(result.Repositories, result.Findings, batch)
		state.Undelivered, state.Findings = addCrawlResult(state.Undelivered, state.Findings, batch)
		if fresh {
			state.Pending = state.Pending[1:]
			state.LastID = item.ID
			state.Scanned++
		} else {
			state.Retry = state.Retry[1:]
			retriesAvailable--
		}
		if len(batch.Repositories) == 0 || batch.Repositories[0].Status == kopis.RepositoryPartial || batch.Repositories[0].Status == kopis.RepositoryUnscanned {
			item.Attempts++
			if item.Attempts >= maxCrawlAttempts {
				state.Gaps = append(state.Gaps, item)
			} else {
				state.Retry = append(state.Retry, item)
			}
		}
		if err := saveCrawl(path, state); err != nil {
			return result, err
		}
		processed++
		if progress != nil {
			progress(processed, batchSize)
		}
	}
	result.Crawl = &kopis.CrawlCoverage{Provider: request.Provider, Instance: instance, LastID: state.LastID, EndID: state.EndID, Scanned: state.Scanned, Pending: len(state.Pending) + len(state.Retry), Gaps: len(state.Gaps), DiscoveryFailure: discoveryFailure, EnumerationDone: state.EnumerationDone, Complete: discoveryFailure == "" && state.EnumerationDone && len(state.Pending) == 0 && len(state.Retry) == 0 && len(state.Gaps) == 0}
	for _, gap := range state.Gaps {
		result.Crawl.GapRepositories = append(result.Crawl.GapRepositories, gap.Repository.ID)
	}
	return result, nil
}
