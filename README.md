# Kopis

Kopis scans authorized GitHub and GitLab repositories for exposed credentials in AI-tool configuration and executable files. It inspects catalog-matched files on each repository's default branch; Markdown (`.md`, `.mdx`) is excluded.

## Run

Set `GITHUB_TOKEN` or `GITLAB_TOKEN`, then run:

```sh
# Scan a specific repository (including private repositories your token can access).
go run ./cmd/kopis -provider github -scope owner/repo
go run ./cmd/kopis -provider gitlab -scope group/project

# Crawl public repositories in batches; repeat with the same checkpoint.
go run ./cmd/kopis -provider github -checkpoint ./github-crawl.json -format jsonl -o ./batch.jsonl

# Find likely GitHub repositories quickly (incomplete coverage).
go run ./cmd/kopis -provider github -search-leads -format jsonl
```

Without `-scope`, `-scope-file`, or `-token-associated`, Kopis crawls public repositories on the selected provider instance (GitLab.com by default). Use `-token-associated` to scan repositories associated with your token instead. `-base-url` selects another provider instance; `-token-env` selects another token variable.

## Coverage and output

Keep the same checkpoint across public crawl batches. Each report contains that run's findings, so use a different `-o` file for each batch (`-o` overwrites). After a completed pass, use `-new-pass` to look for newer repositories. Use a fresh checkpoint to revisit exhausted gaps or rescan after detector changes. Exit code 2 means coverage is incomplete; failed repositories remain identified as gaps. Kopis does not scan history or perform comprehensive secret detection.

`-search-leads` uses GitHub's **legacy REST code search** (`/search/code`) to select repositories for the normal scan. Its queries use `filename:` for filenames; GitHub's newer **website** Code Search uses `path:` instead. Lead search is indexed and capped, never establishes complete coverage, and does not advance the crawl checkpoint. By default it runs one query and one page; use `-lead-start N`, `-lead-queries N`, or `-lead-page N` to request more results. Exit code 2 is expected.

Reports go to standard output by default (`-format jsonl` for JSONL); `-o` writes to a file. Use `-explain` to see discovery and retrieval counts on standard error. Findings include source locations and fingerprints, not credential values. `no_findings` means inspected files had no reported finding, not that the repository is safe.
