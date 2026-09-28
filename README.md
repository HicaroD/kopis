# Kopis

The name comes from the *kopis*, an ancient Greek curved sword.

Kopis scans authorized GitHub or GitLab repositories for credential exposure in a catalog of AI-tool configuration and executable files. It lists each repository's default-branch files, matches catalog paths locally, and downloads only candidate files for inspection. Content-gated workflow rules and referenced `{file:...}` targets are checked after their parent files are fetched.

```sh
go run ./cmd/kopis -provider github -format jsonl
go run ./cmd/kopis -provider gitlab -scope group/project
go run ./cmd/kopis -provider github -scope owner/repo -explain
go run ./cmd/kopis -provider github -scope owner/repo -o report.txt
go run ./cmd/kopis -provider github -scope owner/repo -format jsonl -o report.jsonl
# Find likely AI-tool repositories quickly, then inspect each with the normal tree scan.
go run ./cmd/kopis -provider github -search-leads -format jsonl
```

Set `GITHUB_TOKEN` or `GITLAB_TOKEN` in the environment (or use `-token-env` to name another variable). With no scope, Kopis crawls **public** repositories on the selected provider instance in bounded batches. GitHub uses `/repositories` with a `since` ID; GitLab uses public-project keyset pagination on `-base-url` (GitLab.com by default). A GitLab.com scan does not cover other GitLab instances. To retain the earlier token-associated scan of owned, member, and collaborator repositories, pass `-token-associated`. Use `-scope` or `-scope-file` to scan specified repositories, including ones your token can access privately.

```sh
# Run repeatedly with the same checkpoint until coverage is complete.
go run ./cmd/kopis -provider github -batch-size 100 -checkpoint ./github-crawl.json -format jsonl -o ./batch.jsonl
go run ./cmd/kopis -provider gitlab -base-url https://gitlab.com -batch-size 100 -checkpoint ./gitlab-crawl.json
# Once a pass is complete, start a pass for repositories created afterward.
go run ./cmd/kopis -provider github -checkpoint ./github-crawl.json -new-pass
# The previous token-associated default is still available explicitly.
go run ./cmd/kopis -provider github -token-associated
```

The default checkpoint filename is derived from the provider and instance URL. Keep the same checkpoint across runs; `-new-pass` requires the preceding pass to be complete. Batch reports contain findings **from that run** (plus any undelivered findings from a failed report write), cumulative crawl counts, and exhausted repository IDs in `crawl.gap_repositories`; retain each batch report if you need a combined findings history. `-o` replaces its destination, so use distinct filenames for retained batches. Checkpoints store public repository identities, progress, and redacted outcomes awaiting a successful report write, not tokens or fetched content. An interrupted run may replay its last uncommitted repository or undelivered report, but will not skip it.

Coverage remains incomplete (exit code 2) until enumeration ends and outstanding repository retries are resolved. Partial or inaccessible repositories are retried in later runs up to three attempts, then remain identified coverage gaps and keep the pass incomplete. To revisit exhausted gaps, start a fresh checkpoint and rescan the public range. Completion describes the enumerated public repository range and catalogued **default-branch** files; it is not a snapshot across simultaneous repository visibility changes. GitHub records its end ID on reaching the end of pagination; GitLab records a public-project upper ID at pass start. New repositories require another pass. Tree truncation, pagination errors, and failed candidate retrieval remain coverage gaps. Kopis does not scan history or perform comprehensive secret detection.

`-search-leads` is a separate GitHub-only, findings-first mode. It runs catalog-derived legacy code-search queries to identify likely repositories, filters paths locally, and then uses the same default-branch inventory and candidate inspection as the crawl. By default it requests one query and one page (at most 100 search matches). The JSONL `leads` section reports raw/eligible/filtered matches, `queries_planned`, `next_query`, `next_page`, and saturated queries; use `-lead-start N` for another query and `-lead-page N` for another page of a single query (up to page 10). `-lead-queries N` runs adjacent queries in one invocation. Search results can be capped, outdated, or absent from GitHub's index, so lead-mode coverage always remains incomplete. The lead run does not advance the crawl checkpoint, and its exit code 2 is expected. Only the crawl establishes the repository enumeration boundary.

The JSON/JSONC inspector walks configuration values (including nested properties and JSONC comments/trailing commas) while preserving file locations. Earlier crawl checkpoints are rejected after this detector change: use a new checkpoint filename to rescan repositories that might have been missed by the former JSON assignment matcher.

Use `-explain` to see content-free repository listing counts and the catalog paths matched, fetched, inspected, or failed on standard error. It helps distinguish discovery and retrieval gaps from inspection gaps. `findings` means the scan reported credential evidence; `no_findings` means a catalogued file was inspected without a reported finding, not that the repository is free of secrets. Findings report source locations and fingerprints without printing matched credential values.

Terminal output groups repeated findings by file and type, showing all source locations with shared guidance once. JSONL keeps each occurrence as a separate finding. By default the report goes to standard output; `-o` writes the selected format to a file and replaces an existing report. Progress and `-explain` details remain on standard error.
