package kopis

import (
	"context"
	"strconv"
	"strings"
)

// GitHubLeadResult describes indexed discovery only. Even a fully returned
// query cannot establish that every matching public repository was indexed.
type GitHubLeadResult struct {
	Repositories    []Repository
	QueriesPlanned  int
	QueriesRun      int
	NextQuery       int
	NextPage        int
	RawMatches      int
	EligibleMatches int
	FilteredMatches int
	Saturated       []string
	Failures        []string
	Complete        bool
}

type githubLeadQuery struct {
	text  string
	match func(string) bool
}

func githubCatalogLeadQueries(catalog []Artifact) []githubLeadQuery {
	var queries []githubLeadQuery
	add := func(ruleID, query string, match func(string) bool) {
		if catalogAllows(catalog, ruleID) {
			queries = append(queries, githubLeadQuery{text: query, match: match})
		}
	}
	exact := func(expected string) func(string) bool { return func(path string) bool { return path == expected } }
	under := func(prefix string) func(string) bool {
		return func(path string) bool { return strings.HasPrefix(path, prefix) }
	}
	add("opencode.config", "filename:opencode.json", exact("opencode.json"))
	add("opencode.config", "filename:opencode.jsonc", exact("opencode.jsonc"))
	add("claude.mcp", "filename:.mcp.json", func(p string) bool { return p == ".mcp.json" || strings.HasSuffix(p, "/.mcp.json") })
	add("claude.settings", "filename:settings.json path:.claude", exact(".claude/settings.json"))
	add("codex.config", "filename:config.toml path:.codex", func(p string) bool { return p == ".codex/config.toml" || strings.HasSuffix(p, "/.codex/config.toml") })
	add("antigravity.mcp", "filename:mcp_config.json path:.agents", exact(".agents/mcp_config.json"))
	add("gemini.extension", "filename:gemini-extension.json", func(p string) bool {
		return p == "gemini-extension.json" || strings.HasSuffix(p, "/gemini-extension.json")
	})
	add("gemini.settings", "filename:settings.json path:.gemini", exact(".gemini/settings.json"))
	add("antigravity.hooks", "filename:hooks.json path:.agents", exact(".agents/hooks.json"))
	add("opencode.plugin", "opencode in:path path:.opencode/plugins", func(p string) bool {
		return strings.HasPrefix(p, ".opencode/plugins/") && hasExtension(p, ".js", ".jsx", ".ts", ".tsx")
	})
	add("opencode.tool", "opencode in:path path:.opencode/tools", under(".opencode/tools/"))
	add("gemini.commands", "gemini in:path path:.gemini/commands", func(p string) bool {
		return strings.HasPrefix(p, ".gemini/commands/") && hasExtension(p, ".toml")
	})
	add("gemini.skills", "gemini in:path path:.gemini/skills", under(".gemini/skills/"))
	add("antigravity.skills", "agents in:path path:.agents/skills", under(".agents/skills/"))
	add("antigravity.rules", "agents in:path path:.agents/rules", under(".agents/rules/"))
	add("opencode.workflow", "opencode in:file path:.github/workflows", workflowLeadPath)
	add("codex.workflow", "codex in:file path:.github/workflows", workflowLeadPath)
	return queries
}

func workflowLeadPath(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") && hasExtension(p, ".yml", ".yaml")
}

// SearchLeads inspects one result page per catalog-derived query, starting at
// queryStart. Later pages and queries can be requested in future lead runs;
// neither a search result nor an empty search response proves scan coverage.
func (c *GitHubClient) SearchLeads(ctx context.Context, catalog []Artifact, queryStart, queryLimit int) GitHubLeadResult {
	return c.SearchLeadsAt(ctx, catalog, queryStart, queryLimit, 1)
}

// SearchLeadsAt requests a later page of a single query when page > 1.
func (c *GitHubClient) SearchLeadsAt(ctx context.Context, catalog []Artifact, queryStart, queryLimit, page int) GitHubLeadResult {
	queries := githubCatalogLeadQueries(catalog)
	result := GitHubLeadResult{QueriesPlanned: len(queries), NextQuery: queryStart}
	if queryStart < 0 || queryStart > len(queries) || queryLimit < 1 || page < 1 || page > 10 || page > 1 && queryLimit != 1 || c == nil || c.baseURL == nil || c.token == "" {
		result.Failures = append(result.Failures, "invalid lead search request")
		return result
	}
	end := min(queryStart+queryLimit, len(queries))
	seen := make(map[string]bool)
	for i := queryStart; i < end && ctx.Err() == nil; i++ {
		query := queries[i]
		if err := validateGitHubQuery(query.text); err != nil {
			result.Failures = append(result.Failures, "invalid catalog search query")
			result.NextQuery = i + 1
			continue
		}
		pageArg := ""
		if page > 1 {
			pageArg = strconv.Itoa(page)
		}
		response, items, next, failure := c.searchPage(ctx, c.searchURL(query.text, pageArg))
		result.QueriesRun++
		result.NextQuery = i + 1
		if failure != nil {
			result.Failures = append(result.Failures, failure.Kind)
			continue
		}
		if next != "" || response.TotalCount > (page-1)*githubPageSize+len(items) || response.IncompleteResults {
			result.Saturated = append(result.Saturated, query.text)
		}
		if next != "" && page < 10 && queryLimit == 1 {
			result.NextQuery = i
			result.NextPage = page + 1
		}
		for _, item := range items {
			result.RawMatches++
			id := item.Repository.FullName
			if !query.match(item.Path) || id == "" || item.Repository.Private {
				result.FilteredMatches++
				continue
			}
			result.EligibleMatches++
			if seen[id] {
				continue
			}
			seen[id] = true
			result.Repositories = append(result.Repositories, Repository{Provider: GitHubProvider, ID: id, URL: safeURL(item.Repository.HTMLURL), Public: true, Accessible: true})
		}
	}
	return result
}
