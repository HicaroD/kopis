# Kopis

The name comes from the *kopis*, an ancient Greek curved sword.

Kopis scans authorized GitHub or GitLab repositories for credential exposure in a catalog of AI-tool configuration and executable files. It lists each repository's default-branch files, matches catalog paths locally, and downloads only candidate files for inspection. Content-gated workflow rules and referenced `{file:...}` targets are checked after their parent files are fetched.

```sh
go run ./cmd/kopis -provider github -format jsonl
go run ./cmd/kopis -provider gitlab -scope group/project
go run ./cmd/kopis -provider github -scope owner/repo -explain
go run ./cmd/kopis -provider github -scope owner/repo -o report.txt
go run ./cmd/kopis -provider github -scope owner/repo -format jsonl -o report.jsonl
```

Set `GITHUB_TOKEN` or `GITLAB_TOKEN` in the environment (or use `-token-env` to name another variable). Omit `-scope` to scan accessible repositories in the authorized default scope; use `-scope-file` for a repository list. The scan reports partial coverage when a tree listing is truncated, pagination fails, or a candidate file cannot be retrieved. It inspects the default branch's catalogued files only; it does not scan history or perform comprehensive secret detection.

Use `-explain` to see content-free repository listing counts and the catalog paths matched, fetched, inspected, or failed on standard error. It helps distinguish discovery and retrieval gaps from inspection gaps. `findings` means the scan reported credential evidence; `no_findings` means a catalogued file was inspected without a reported finding, not that the repository is free of secrets. Findings report source locations and fingerprints without printing matched credential values.

Terminal output groups repeated findings by file and type, showing all source locations with shared guidance once. JSONL keeps each occurrence as a separate finding. By default the report goes to standard output; `-o` writes the selected format to a file and replaces an existing report. Progress and `-explain` details remain on standard error.
