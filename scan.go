package kopis

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
)

const (
	RepositoryNoFindings           = "no_findings"
	RepositoryNoCandidateArtifacts = "no_candidate_artifacts"
	RepositoryPartial              = "partial"
	RepositoryUnscanned            = "unscanned"

	ScopeDefault    = "default"
	ScopeRepository = "repository"
	ScopeList       = "list"
)

// Repository is the provider's safe, non-content view of a repository.
type Repository struct {
	Provider     string
	ID           string
	URL          string
	Public       bool
	Owner        bool
	Member       bool
	Collaborator bool
	Accessible   bool
}

// Scope narrows the default authorized repository set. IDs are provider
// canonical identifiers, one per entry.
type Scope struct {
	Kind          string
	RepositoryIDs []string
}

// ParseScope reads the explicit repository-list format used by file and stdin
// scope sources. Empty lines and lines beginning with '#' are ignored.
func ParseScope(reader io.Reader) (Scope, error) {
	if reader == nil {
		return Scope{}, errors.New("scope reader is required")
	}
	seen := make(map[string]bool)
	var ids []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		id := strings.TrimSpace(scanner.Text())
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if err := scanner.Err(); err != nil {
		return Scope{}, err
	}
	if len(ids) == 0 {
		return Scope{}, errors.New("scope contains no repositories")
	}
	kind := ScopeList
	if len(ids) == 1 {
		kind = ScopeRepository
	}
	return Scope{Kind: kind, RepositoryIDs: ids}, nil
}

// SearchOutcome is the provider-neutral result of one catalog-derived search.
type SearchOutcome struct {
	Candidates  []Candidate
	Complete    bool
	Denied      bool
	Unavailable bool
}

// ScanProvider supplies authorization-aware repository discovery and
// catalog-only searches. Implementations must not return protected content in
// errors or discovery failures.
type ScanProvider interface {
	Discover(ctx context.Context, token string) ([]Repository, error)
	Search(ctx context.Context, token string, repository Repository, query string, artifact Artifact) SearchOutcome
}

type ScanRequest struct {
	Provider     string
	Token        string
	Scope        Scope
	Catalog      []Artifact
	Repositories []Repository
	Scanner      ScanProvider
	Concurrency  int
}

type RepositoryResult struct {
	Repository Repository
	Status     string
	Findings   []Finding
}

type ScanResult struct {
	Repositories []RepositoryResult
	Findings     []Finding
}

// Scan performs authorized, catalog-derived discovery and targeted inspection.
// Tokens are used only during the call and are absent from the result.
func Scan(ctx context.Context, request ScanRequest) (ScanResult, error) {
	if strings.TrimSpace(request.Provider) == "" || strings.TrimSpace(request.Token) == "" {
		return ScanResult{}, errors.New("provider and runtime token are required")
	}
	if request.Scanner == nil {
		return ScanResult{}, errors.New("scan provider is required")
	}
	if request.Scope.Kind == "" {
		request.Scope.Kind = ScopeDefault
	}
	if request.Scope.Kind != ScopeDefault && (len(request.Scope.RepositoryIDs) == 0 || (request.Scope.Kind != ScopeRepository && request.Scope.Kind != ScopeList)) {
		return ScanResult{}, errors.New("invalid repository scope")
	}

	repositories := request.Repositories
	if repositories == nil {
		var err error
		repositories, err = request.Scanner.Discover(ctx, request.Token)
		if err != nil {
			if request.Scope.Kind != ScopeDefault {
				results := make([]RepositoryResult, 0, len(request.Scope.RepositoryIDs))
				for _, id := range request.Scope.RepositoryIDs {
					results = append(results, RepositoryResult{Repository: Repository{Provider: request.Provider, ID: id}, Status: RepositoryUnscanned})
				}
				return ScanResult{Repositories: results}, nil
			}
			return ScanResult{}, errors.New("repository discovery failed")
		}
	}
	selected, invalid := selectRepositories(repositories, request.Provider, request.Scope)
	results := make([]RepositoryResult, 0, len(selected)+len(invalid))
	seenInvalid := make(map[string]bool, len(invalid))
	for _, repository := range invalid {
		repository.Status = RepositoryUnscanned
		results = append(results, repository)
		seenInvalid[repository.Repository.ID] = true
	}
	if request.Scope.Kind != ScopeDefault {
		for _, id := range request.Scope.RepositoryIDs {
			if !seenInvalid[id] && !containsRepository(selected, id) {
				results = append(results, RepositoryResult{Repository: Repository{Provider: request.Provider, ID: id}, Status: RepositoryUnscanned})
			}
		}
	}

	workers := request.Concurrency
	if workers < 1 {
		workers = 4
	}
	if workers > len(selected) {
		workers = len(selected)
	}
	type indexed struct {
		index  int
		result RepositoryResult
	}
	jobs := make(chan indexed)
	output := make(chan indexed, len(selected))
	var wait sync.WaitGroup
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for job := range jobs {
				output <- indexed{index: job.index, result: scanRepository(ctx, request, job.result.Repository)}
			}
		}()
	}
	go func() {
		for i, repository := range selected {
			jobs <- indexed{index: i, result: RepositoryResult{Repository: repository}}
		}
		close(jobs)
		wait.Wait()
		close(output)
	}()
	ordered := make([]RepositoryResult, len(selected))
	for item := range output {
		ordered[item.index] = item.result
	}
	results = append(results, ordered...)
	sort.SliceStable(results, func(i, j int) bool { return results[i].Repository.ID < results[j].Repository.ID })
	var findings []Finding
	for _, result := range results {
		findings = append(findings, result.Findings...)
	}
	return ScanResult{Repositories: results, Findings: findings}, nil
}

func selectRepositories(repositories []Repository, provider string, scope Scope) ([]Repository, []RepositoryResult) {
	wanted := make(map[string]bool, len(scope.RepositoryIDs))
	for _, id := range scope.RepositoryIDs {
		wanted[id] = true
	}
	var selected []Repository
	var invalid []RepositoryResult
	for _, repository := range repositories {
		if repository.Provider != provider || repository.ID == "" {
			continue
		}
		if scope.Kind == ScopeDefault {
			if (repository.Owner || repository.Member || repository.Collaborator) && repository.Accessible {
				selected = append(selected, repository)
			} else if repository.Owner || repository.Member || repository.Collaborator {
				invalid = append(invalid, RepositoryResult{Repository: repository})
			}
			continue
		}
		if !wanted[repository.ID] {
			continue
		}
		if !repository.Accessible {
			invalid = append(invalid, RepositoryResult{Repository: repository})
			continue
		}
		selected = append(selected, repository)
	}
	return selected, invalid
}

func containsRepository(repositories []Repository, id string) bool {
	for _, repository := range repositories {
		if repository.ID == id {
			return true
		}
	}
	return false
}

func scanRepository(ctx context.Context, request ScanRequest, repository Repository) RepositoryResult {
	result := RepositoryResult{Repository: repository, Status: RepositoryNoCandidateArtifacts}
	if !repository.Accessible && request.Scope.Kind != ScopeDefault {
		result.Status = RepositoryUnscanned
		return result
	}
	seen := make(map[string]bool)
	started, incomplete, foundCandidate := false, false, false
	for _, artifact := range request.Catalog {
		query := catalogQuery(request.Provider, artifact)
		if query == "" {
			continue
		}
		started = true
		outcome := request.Scanner.Search(ctx, request.Token, repository, query, artifact)
		if !outcome.Complete || outcome.Unavailable {
			incomplete = true
		}
		if outcome.Denied {
			result.Status = RepositoryUnscanned
			return result
		}
		for _, candidate := range outcome.Candidates {
			if candidate.Provider == "" {
				candidate.Provider = request.Provider
			}
			if candidate.Repository == "" {
				candidate.Repository = repository.ID
			}
			key := strings.Join([]string{candidate.Provider, candidate.Repository, candidate.Revision, candidate.Path}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			foundCandidate = true
			result.Findings = append(result.Findings, InspectCandidate(candidate)...)
		}
	}
	if incomplete {
		result.Status = RepositoryPartial
	} else if foundCandidate || len(result.Findings) > 0 {
		result.Status = RepositoryNoFindings
	} else if started {
		result.Status = RepositoryNoCandidateArtifacts
	}
	return result
}

func catalogQuery(provider string, artifact Artifact) string {
	if artifact.Path == "" {
		return ""
	}
	if provider == GitHubProvider {
		return "path:" + artifact.Path
	}
	return artifact.Path
}
