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
	RepositoryFindings             = "findings"
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

// RepositoryFile is a path on a pinned default-branch tree. Revision is the
// blob identity for GitHub and the commit identity for GitLab.
type RepositoryFile struct {
	Path     string
	Revision string
}

type FileListing struct {
	Files    []RepositoryFile
	Complete bool
	Denied   bool
}

type FileOutcome struct {
	Content  string
	Complete bool
	Denied   bool
}

// ScanProvider supplies authorization-aware discovery, a default-branch path
// inventory and pinned file retrieval.
type ScanProvider interface {
	Discover(ctx context.Context, token string) ([]Repository, error)
	ListFiles(ctx context.Context, token string, repository Repository) FileListing
	FetchFile(ctx context.Context, token string, repository Repository, file RepositoryFile) FileOutcome
}

// ExplicitRepositoryProvider resolves an explicitly requested repository
// without relying on the provider's default membership enumeration.
type ExplicitRepositoryProvider interface {
	ResolveRepository(ctx context.Context, token, id string) (Repository, error)
}

type ScanRequest struct {
	Provider     string
	Token        string
	Scope        Scope
	Catalog      []Artifact
	Repositories []Repository
	Scanner      ScanProvider
	Concurrency  int
	// Progress reports completed repositories out of the total selected.
	// Callbacks may be invoked by multiple scan workers.
	Progress func(completed, total int)
}

type RepositoryResult struct {
	Repository  Repository
	Status      string
	Findings    []Finding
	Diagnostics ScanDiagnostics
}

// ScanDiagnostics records metadata-only handoffs. It never holds file content,
// request tokens, matched values, or provider error bodies.
type ScanDiagnostics struct {
	ListedFiles     int
	ListingComplete bool
	MatchedPaths    []string
	FetchedPaths    []string
	InspectedPaths  []string
	FailedPaths     []string
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
	if repositories == nil && request.Scope.Kind != ScopeDefault {
		if resolver, ok := request.Scanner.(ExplicitRepositoryProvider); ok {
			var invalid []RepositoryResult
			for _, id := range request.Scope.RepositoryIDs {
				repository, err := resolver.ResolveRepository(ctx, request.Token, id)
				if err != nil {
					invalid = append(invalid, RepositoryResult{Repository: Repository{Provider: request.Provider, ID: id}, Status: RepositoryUnscanned})
					continue
				}
				if repository.Provider == "" {
					repository.Provider = request.Provider
				}
				if repository.ID == "" {
					repository.ID = id
				}
				if !repository.Accessible {
					invalid = append(invalid, RepositoryResult{Repository: repository, Status: RepositoryUnscanned})
					continue
				}
				repositories = append(repositories, repository)
			}
			results := invalid
			selected, _ := selectRepositories(repositories, request.Provider, request.Scope)
			return scanSelectedRepositories(ctx, request, selected, results)
		}
	}
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

	return scanSelectedRepositories(ctx, request, selected, results)
}

func scanSelectedRepositories(ctx context.Context, request ScanRequest, selected []Repository, results []RepositoryResult) (ScanResult, error) {
	if len(selected) == 0 {
		sort.SliceStable(results, func(i, j int) bool { return results[i].Repository.ID < results[j].Repository.ID })
		return ScanResult{Repositories: results}, nil
	}
	workers := request.Concurrency
	if workers < 1 {
		workers = 4
	}
	if workers > len(selected) {
		workers = len(selected)
	}
	total := len(selected)
	var progressMu sync.Mutex
	completed := 0
	progress := func() {
		if request.Progress != nil {
			progressMu.Lock()
			defer progressMu.Unlock()
			completed++
			request.Progress(completed, total)
		}
	}
	if request.Progress != nil {
		request.Progress(0, total)
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
				output <- indexed{index: job.index, result: scanRepository(ctx, request, job.result.Repository, progress)}
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

func scanRepository(ctx context.Context, request ScanRequest, repository Repository, progress func()) RepositoryResult {
	defer progress()
	result := RepositoryResult{Repository: repository, Status: RepositoryNoCandidateArtifacts}
	if !repository.Accessible && request.Scope.Kind != ScopeDefault {
		result.Status = RepositoryUnscanned
		return result
	}
	listing := request.Scanner.ListFiles(ctx, request.Token, repository)
	result.Diagnostics.ListedFiles = len(listing.Files)
	result.Diagnostics.ListingComplete = listing.Complete
	if listing.Denied {
		result.Status = RepositoryUnscanned
		return result
	}
	incomplete := !listing.Complete
	files := make(map[string]RepositoryFile, len(listing.Files))
	contents := make(map[string]string, len(listing.Files))
	for _, file := range listing.Files {
		if file.Path != "" && file.Revision != "" {
			files[file.Path] = file
			contents[file.Path] = ""
		} else {
			incomplete = true
		}
	}
	queue := catalogPathCandidates(contents, request.Catalog)
	result.Diagnostics.MatchedPaths = append(result.Diagnostics.MatchedPaths, queue...)
	fetched := make(map[string]bool)
	successful := make(map[string]bool)
	deferred := make(map[string][]Artifact)
	inspected := make(map[string]bool)
	admitted := false
	inspect := func(artifact Artifact) {
		key := artifact.Path + "\x00" + artifact.Rule.ID
		if inspected[key] {
			return
		}
		inspected[key] = true
		admitted = true
		result.Diagnostics.InspectedPaths = appendUniquePath(result.Diagnostics.InspectedPaths, artifact.Path)
		result.Findings = append(result.Findings, inspectListedFile(request.Provider, repository, files[artifact.Path], artifact, contents[artifact.Path])...)
	}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			incomplete = true
			break
		}
		file := queue[0]
		queue = queue[1:]
		if fetched[file] {
			continue
		}
		fetched[file] = true
		outcome := request.Scanner.FetchFile(ctx, request.Token, repository, files[file])
		if !outcome.Complete {
			incomplete = true
			result.Diagnostics.FailedPaths = append(result.Diagnostics.FailedPaths, file)
			continue
		}
		successful[file] = true
		result.Diagnostics.FetchedPaths = append(result.Diagnostics.FetchedPaths, file)
		contents[file] = outcome.Content
		artifacts := append(RecognizeArtifact(file, contents), deferred[file]...)
		for _, artifact := range artifacts {
			if !catalogAllowsArtifact(request.Catalog, artifact) {
				continue
			}
			if artifact.Path != file {
				if _, exists := files[artifact.Path]; exists {
					if successful[artifact.Path] {
						inspect(artifact)
					} else if !fetched[artifact.Path] {
						deferred[artifact.Path] = append(deferred[artifact.Path], artifact)
						queue = append(queue, artifact.Path)
						result.Diagnostics.MatchedPaths = appendUniquePath(result.Diagnostics.MatchedPaths, artifact.Path)
					}
				}
				continue
			}
			inspect(artifact)
		}
	}
	if incomplete {
		result.Status = RepositoryPartial
	} else if len(result.Findings) > 0 {
		result.Status = RepositoryFindings
	} else if admitted {
		result.Status = RepositoryNoFindings
	}
	return result
}

func appendUniquePath(paths []string, path string) []string {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func inspectListedFile(provider string, repository Repository, file RepositoryFile, artifact Artifact, content string) []Finding {
	return InspectCandidate(Candidate{Provider: provider, Repository: repository.ID, RepositoryURL: repository.URL,
		Revision: file.Revision, Path: file.Path, Content: content, Tool: artifact.Rule.Tool, CatalogRule: artifact.Rule.ID})
}
