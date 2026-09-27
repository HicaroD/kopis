package kopis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ListFiles inventories the default-branch tree without using code search.
func (c *GitHubClient) ListFiles(ctx context.Context, repository string) FileListing {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return FileListing{}
	}
	root := "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	var metadata struct {
		DefaultBranch string `json:"default_branch"`
	}
	if failure := c.getJSON(ctx, c.endpoint(root, nil), &metadata); failure != nil {
		return FileListing{Denied: githubDenied(failure)}
	}
	if metadata.DefaultBranch == "" {
		return FileListing{}
	}
	var commit struct {
		SHA    string `json:"sha"`
		Commit struct {
			Tree struct {
				SHA string `json:"sha"`
			} `json:"tree"`
		} `json:"commit"`
	}
	if failure := c.getJSON(ctx, c.endpoint(root+"/commits/"+url.PathEscape(metadata.DefaultBranch), nil), &commit); failure != nil {
		return FileListing{Denied: githubDenied(failure)}
	}
	if commit.SHA == "" || commit.Commit.Tree.SHA == "" {
		return FileListing{}
	}
	var tree struct {
		Truncated bool `json:"truncated"`
		Tree      *[]struct {
			Path string `json:"path"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"tree"`
	}
	if failure := c.getJSON(ctx, c.endpoint(root+"/git/trees/"+url.PathEscape(commit.Commit.Tree.SHA), url.Values{"recursive": {"1"}}), &tree); failure != nil {
		return FileListing{Denied: githubDenied(failure)}
	}
	if tree.Tree == nil {
		return FileListing{}
	}
	listing := FileListing{Complete: !tree.Truncated}
	for _, item := range *tree.Tree {
		if item.Type == "blob" && item.Path != "" && item.SHA != "" {
			listing.Files = append(listing.Files, RepositoryFile{Path: item.Path, Revision: item.SHA})
		} else if item.Type == "blob" {
			listing.Complete = false
		}
	}
	return listing
}

func (c *GitHubClient) FetchFile(ctx context.Context, repository string, file RepositoryFile) FileOutcome {
	content, failure := c.retrieve(ctx, githubSearchItem{SHA: file.Revision, Repository: githubRepository{FullName: repository}})
	return FileOutcome{Content: content, Complete: failure == nil, Denied: githubDenied(failure)}
}

func (c *GitHubClient) getJSON(ctx context.Context, endpoint string, target any) *GitHubFailure {
	request, err := c.request(ctx, endpoint)
	if err != nil {
		return &GitHubFailure{Kind: "request"}
	}
	response, failure := c.do(request, nil)
	if failure != nil {
		return failure
	}
	defer response.Body.Close()
	if json.NewDecoder(response.Body).Decode(target) != nil {
		return &GitHubFailure{Kind: "invalid_response"}
	}
	return nil
}

func githubDenied(failure *GitHubFailure) bool {
	return failure != nil && (failure.Status == http.StatusUnauthorized || failure.Status == http.StatusForbidden || failure.AccessAmbiguous)
}

// ListFiles paginates a recursive repository tree at a resolved default-branch commit.
func (c *GitLabClient) ListFiles(ctx context.Context, repository string) FileListing {
	root := "/api/v4/projects/" + escapePathValue(repository)
	var metadata struct {
		DefaultBranch string `json:"default_branch"`
	}
	if failure := c.getJSON(ctx, root, nil, &metadata); failure != nil {
		return FileListing{Denied: gitlabDenied(failure)}
	}
	if metadata.DefaultBranch == "" {
		return FileListing{}
	}
	var commit struct {
		ID string `json:"id"`
	}
	if failure := c.getJSON(ctx, root+"/repository/commits/"+escapePathValue(metadata.DefaultBranch), nil, &commit); failure != nil {
		return FileListing{Denied: gitlabDenied(failure)}
	}
	if commit.ID == "" {
		return FileListing{}
	}
	listing := FileListing{}
	page := "1"
	seen := make(map[string]bool)
	for page != "" && !seen[page] {
		seen[page] = true
		query := url.Values{"ref": {commit.ID}, "recursive": {"true"}, "per_page": {strconv.Itoa(gitLabPageSize)}, "page": {page}}
		request, err := c.newRequest(ctx, root+"/repository/tree", query)
		if err != nil {
			return listing
		}
		response, failure := c.do(request, nil)
		if failure != nil {
			listing.Denied = gitlabDenied(failure)
			return listing
		}
		var entries *[]struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		err = json.NewDecoder(response.Body).Decode(&entries)
		next := response.Header.Get("X-Next-Page")
		response.Body.Close()
		if err != nil || entries == nil {
			return listing
		}
		for _, entry := range *entries {
			if entry.Type == "blob" && entry.Path != "" {
				listing.Files = append(listing.Files, RepositoryFile{Path: entry.Path, Revision: commit.ID})
			}
			if entry.Type == "blob" && entry.Path == "" {
				return listing
			}
		}
		if next == "" {
			listing.Complete = true
		}
		page = next
	}
	if page != "" {
		listing.Complete = false
	}
	return listing
}

func (c *GitLabClient) FetchFile(ctx context.Context, repository string, file RepositoryFile) FileOutcome {
	content, failure := c.retrieve(ctx, GitLabBlob{ProjectID: repository, Path: file.Path, Ref: file.Revision})
	return FileOutcome{Content: content, Complete: failure == nil, Denied: gitlabDenied(failure)}
}

func (c *GitLabClient) getJSON(ctx context.Context, endpoint string, query url.Values, target any) *GitLabFailure {
	request, err := c.newRequest(ctx, endpoint, query)
	if err != nil {
		return &GitLabFailure{Kind: "request"}
	}
	response, failure := c.do(request, nil)
	if failure != nil {
		return failure
	}
	defer response.Body.Close()
	if json.NewDecoder(response.Body).Decode(target) != nil {
		return &GitLabFailure{Kind: "invalid_response"}
	}
	return nil
}

func gitlabDenied(failure *GitLabFailure) bool {
	return failure != nil && (failure.Status == http.StatusUnauthorized || failure.Status == http.StatusForbidden || failure.AccessAmbiguous)
}
