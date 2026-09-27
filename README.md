# Kopis

The name comes from the *kopis*, an ancient Greek curved sword.

Kopis scans authorized GitHub or GitLab repositories for credential exposure in a catalog of AI-tool configuration and executable files. It lists each repository's default-branch files, matches catalog paths locally, and downloads only candidate files for inspection. Content-gated workflow rules and referenced `{file:...}` targets are checked after their parent files are fetched.

```sh
go run ./cmd/kopis -provider github -format jsonl
go run ./cmd/kopis -provider gitlab -scope group/project
```

Set `GITHUB_TOKEN` or `GITLAB_TOKEN` in the environment (or use `-token-env` to name another variable). Omit `-scope` to scan accessible repositories in the authorized default scope; use `-scope-file` for a repository list. The scan reports partial coverage when a tree listing is truncated, pagination fails, or a candidate file cannot be retrieved. It inspects the default branch's catalogued files only; it does not scan history or perform comprehensive secret detection.
