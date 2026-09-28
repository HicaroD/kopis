package kopis

import (
	"encoding/json"
	"path"
	"sort"
	"strings"
)

// Tool names are stable identifiers used by catalog rules and findings.
const (
	ToolOpenCode    = "opencode"
	ToolClaudeCode  = "claude-code"
	ToolCodex       = "codex"
	ToolAntigravity = "antigravity"
	ToolGeminiCLI   = "gemini-cli"
)

// CatalogRule describes why an artifact is in the inspection boundary.
type CatalogRule struct {
	ID            string
	Tool          string
	Pattern       string
	Indicators    []string
	Rationale     string
	Applicability string
	Confidence    string
}

// Artifact is a catalogued repository file and the rule that admitted it.
type Artifact struct {
	Path string
	Rule CatalogRule
}

// InitialCatalog returns the concrete catalog entries used by the CLI's
// provider searches. Dynamic directory rules remain enforced by recognition.
func InitialCatalog() []Artifact {
	entries := []struct{ path, id, tool, pattern, indicator string }{
		{"opencode.json", "opencode.config", ToolOpenCode, "project-root opencode configuration", "credential_fields"},
		{"opencode.jsonc", "opencode.config", ToolOpenCode, "project-root opencode configuration", "credential_fields"},
		{".opencode/plugins/index.ts", "opencode.plugin", ToolOpenCode, "OpenCode plugin", "executable"},
		{".opencode/tools/tool.ts", "opencode.tool", ToolOpenCode, "OpenCode custom tool", "executable"},
		{".github/workflows/opencode.yml", "opencode.workflow", ToolOpenCode, "workflow using anomalyco/opencode/github", "workflow_provider_key"},
		{".mcp.json", "claude.mcp", ToolClaudeCode, "project-root Claude MCP configuration", "credential_fields"},
		{".claude/settings.json", "claude.settings", ToolClaudeCode, "Claude project settings", "credential_fields"},
		{".codex/config.toml", "codex.config", ToolCodex, "Codex configuration", "credential_fields"},
		{".github/workflows/codex.yml", "codex.workflow", ToolCodex, "workflow using openai/codex-action", "workflow_provider_key"},
		{".agents/mcp_config.json", "antigravity.mcp", ToolAntigravity, "Antigravity MCP configuration", "credential_fields"},
		{".agents/hooks.json", "antigravity.hooks", ToolAntigravity, "Antigravity hooks", "executable"},
		{".agents/skills/example/scripts/check.ts", "antigravity.skills", ToolAntigravity, "Antigravity skill assets", "executable"},
		{".agents/rules/check.js", "antigravity.rules", ToolAntigravity, "Antigravity rule assets", "executable"},
		{".gemini/settings.json", "gemini.settings", ToolGeminiCLI, "Gemini CLI settings", "credential_fields"},
		{".gemini/commands/default.toml", "gemini.commands", ToolGeminiCLI, "Gemini CLI commands", "executable"},
		{"gemini-extension.json", "gemini.extension", ToolGeminiCLI, "Gemini extension manifest", "credential_fields"},
		{".gemini/skills/example/scripts/check.ts", "gemini.skills", ToolGeminiCLI, "Gemini CLI skill assets", "executable"},
	}
	result := make([]Artifact, 0, len(entries))
	for _, entry := range entries {
		result = append(result, Artifact{Path: entry.path, Rule: CatalogRule{ID: entry.id, Tool: entry.tool, Pattern: entry.pattern, Indicators: []string{entry.indicator}, Applicability: "initial evidence-backed catalog", Confidence: "catalogued artifact only"}})
	}
	return result
}

// CataloguedFiles returns every file admitted by the initial evidence-backed
// catalog. Contents are used only for pairing rules and file substitutions.
func CataloguedFiles(files map[string]string) []Artifact {
	var result []Artifact
	filenames := make([]string, 0, len(files))
	for filename := range files {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	for _, filename := range filenames {
		result = append(result, catalogMatches(filename, files[filename], files)...)
	}
	return result
}

// catalogPathCandidates is a conservative prefilter: content-gated workflows
// are fetched before their action reference can be checked. Marker-backed
// files are selected using the path inventory alone.
func catalogPathCandidates(files map[string]string, catalog []Artifact) []string {
	paths := make([]string, 0, len(files))
	for filename := range files {
		paths = append(paths, filename)
	}
	sort.Strings(paths)
	var selected []string
	for _, filename := range paths {
		eligible := false
		for _, artifact := range RecognizeArtifact(filename, files) {
			if artifact.Path == filename && catalogAllowsArtifact(catalog, artifact) {
				eligible = true
			}
		}
		p := slashPath(filename)
		if strings.HasPrefix(p, ".github/workflows/") && hasExtension(p, ".yml", ".yaml") &&
			(catalogAllows(catalog, "opencode.workflow") || catalogAllows(catalog, "codex.workflow")) {
			eligible = true
		}
		if eligible {
			selected = append(selected, filename)
		}
	}
	return selected
}

var parentCatalogRule = map[string]string{
	"opencode.file-substitution": "opencode.config",
	"claude.plugin-mcp":          "claude.mcp",
	"gemini.extension-hooks":     "gemini.extension",
	"gemini.extension-assets":    "gemini.extension",
	"gemini.extension-env":       "gemini.extension",
}

func catalogAllows(catalog []Artifact, id string) bool {
	parent := parentCatalogRule[id]
	for _, artifact := range catalog {
		if artifact.Rule.ID == id || parent != "" && artifact.Rule.ID == parent {
			return true
		}
	}
	return false
}

func catalogAllowsArtifact(catalog []Artifact, candidate Artifact) bool {
	if isMarkdownPath(candidate.Path) {
		return false
	}
	if !catalogAllows(catalog, candidate.Rule.ID) {
		return false
	}
	switch candidate.Rule.ID {
	case "opencode.config", "claude.mcp", "claude.settings", "antigravity.mcp", "antigravity.hooks", "gemini.settings":
		for _, source := range catalog {
			if source.Rule.ID == candidate.Rule.ID && source.Path == candidate.Path {
				return true
			}
		}
		return false
	}
	return true
}

// RecognizeArtifact applies the catalog to one repository path.
func RecognizeArtifact(filename string, files map[string]string) []Artifact {
	return catalogMatches(filename, files[filename], files)
}

func catalogMatches(filename, content string, files map[string]string) []Artifact {
	p := slashPath(filename)
	if isMarkdownPath(p) {
		return nil
	}
	var rules []CatalogRule
	switch {
	case p == "opencode.json" || p == "opencode.jsonc":
		rules = append(rules, rule("opencode.config", ToolOpenCode, "project-root opencode configuration", "credential_fields"))
	case strings.HasPrefix(p, ".opencode/plugins/") && hasExtension(p, ".js", ".jsx", ".ts", ".tsx"):
		rules = append(rules, rule("opencode.plugin", ToolOpenCode, "OpenCode plugin", "executable"))
	case strings.HasPrefix(p, ".opencode/tools/") && hasExtension(p, ".js", ".jsx", ".ts", ".tsx"):
		rules = append(rules, rule("opencode.tool", ToolOpenCode, "OpenCode custom tool", "executable"))
	case strings.HasPrefix(p, ".github/workflows/") && hasExtension(p, ".yml", ".yaml") && workflowAction(content, "anomalyco/opencode/github"):
		rules = append(rules, rule("opencode.workflow", ToolOpenCode, "workflow using anomalyco/opencode/github", "workflow_provider_key"))
	case p == ".mcp.json":
		rules = append(rules, rule("claude.mcp", ToolClaudeCode, "project-root Claude MCP configuration", "credential_fields"))
	case p == ".claude/settings.json":
		rules = append(rules, rule("claude.settings", ToolClaudeCode, "Claude project settings", "credential_fields"))
	case path.Base(p) == ".mcp.json" && claudePluginRootExists(p, files):
		rules = append(rules, rule("claude.plugin-mcp", ToolClaudeCode, "Claude plugin MCP configuration", "credential_fields"))
	case strings.HasSuffix(p, "/.codex/config.toml") || p == ".codex/config.toml":
		rules = append(rules, rule("codex.config", ToolCodex, "Codex configuration", "credential_fields"))
	case strings.HasPrefix(p, ".github/workflows/") && hasExtension(p, ".yml", ".yaml") && workflowAction(content, "openai/codex-action"):
		rules = append(rules, rule("codex.workflow", ToolCodex, "workflow using openai/codex-action", "workflow_provider_key"))
	case p == ".agents/mcp_config.json":
		rules = append(rules, rule("antigravity.mcp", ToolAntigravity, "Antigravity MCP configuration", "credential_fields"))
	case p == ".agents/hooks.json":
		rules = append(rules, rule("antigravity.hooks", ToolAntigravity, "Antigravity hooks", "executable"))
	case strings.HasPrefix(p, ".agents/skills/"):
		rules = append(rules, rule("antigravity.skills", ToolAntigravity, "Antigravity skills", "executable"))
	case strings.HasPrefix(p, ".agents/rules/"):
		rules = append(rules, rule("antigravity.rules", ToolAntigravity, "Antigravity rules", "executable"))
	case p == ".gemini/settings.json":
		rules = append(rules, rule("gemini.settings", ToolGeminiCLI, "Gemini CLI settings", "credential_fields"))
	case strings.HasPrefix(p, ".gemini/commands/") && strings.HasSuffix(p, ".toml"):
		rules = append(rules, rule("gemini.commands", ToolGeminiCLI, "Gemini CLI commands", "executable"))
	case strings.HasSuffix(p, "/gemini-extension.json") || p == "gemini-extension.json":
		rules = append(rules, rule("gemini.extension", ToolGeminiCLI, "Gemini extension manifest", "credential_fields"))
	case strings.HasSuffix(p, "/hooks/hooks.json") || p == "hooks/hooks.json":
		if extensionRootExists(p, files) {
			rules = append(rules, rule("gemini.extension-hooks", ToolGeminiCLI, "Gemini extension hooks", "executable"))
		}
	case isGeminiExtensionAsset(p) && extensionRootExists(p, files):
		rules = append(rules, rule("gemini.extension-assets", ToolGeminiCLI, "Gemini extension executable or skill asset", "executable"))
	case strings.HasPrefix(p, ".gemini/skills/"):
		rules = append(rules, rule("gemini.skills", ToolGeminiCLI, "Gemini CLI skills", "executable"))
	case path.Base(p) == ".env" && extensionRootExists(p, files):
		rules = append(rules, rule("gemini.extension-env", ToolGeminiCLI, "Gemini extension environment", "credential_fields"))
	}
	if strings.HasPrefix(p, ".agents/skills/") {
		rules = append(rules, rule("gemini.skills", ToolGeminiCLI, "Gemini CLI skills", "executable"))
	}
	result := make([]Artifact, 0, len(rules))
	for _, r := range rules {
		result = append(result, Artifact{Path: filename, Rule: r})
	}
	if p == "opencode.json" || p == "opencode.jsonc" {
		for _, referenced := range fileSubstitutions(content) {
			if _, ok := files[referenced]; ok && !isMarkdownPath(referenced) {
				result = append(result, Artifact{Path: referenced, Rule: rule("opencode.file-substitution", ToolOpenCode, "repository-relative {file:...} target", "credential_fields")})
			}
		}
	}
	return result
}

func claudePluginRootExists(p string, files map[string]string) bool {
	parts := strings.Split(slashPath(p), "/")
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := files[strings.Join(parts[:i+1], "/")+"/.claude-plugin/plugin.json"]; ok {
			return true
		}
	}
	return false
}

func rule(id, tool, pattern, indicator string) CatalogRule {
	return CatalogRule{ID: id, Tool: tool, Pattern: pattern, Indicators: []string{indicator}, Applicability: "initial evidence-backed catalog", Confidence: "catalogued artifact only"}
}

func slashPath(s string) string { return strings.TrimPrefix(strings.ReplaceAll(s, "\\", "/"), "./") }

func isMarkdownPath(s string) bool {
	extension := path.Ext(slashPath(s))
	return strings.EqualFold(extension, ".md") || strings.EqualFold(extension, ".mdx")
}

func hasExtension(s string, extensions ...string) bool {
	for _, extension := range extensions {
		if strings.HasSuffix(s, extension) {
			return true
		}
	}
	return false
}

func isGeminiExtensionAsset(p string) bool {
	return strings.Contains("/"+p, "/commands/") || strings.Contains("/"+p, "/skills/") || strings.Contains("/"+p, "/hooks/")
}

func extensionRootExists(p string, files map[string]string) bool {
	parts := strings.Split(slashPath(p), "/")
	for i := range parts {
		candidate := strings.Join(parts[:i+1], "/") + "/gemini-extension.json"
		if _, ok := files[candidate]; ok {
			return true
		}
	}
	return false
}

func fileSubstitutions(content string) []string {
	// Substitutions only exist in configuration values, not comments or keys.
	source := stripJSONComments(content)
	var config any
	if json.Unmarshal([]byte(source), &config) != nil {
		return nil
	}
	var result []string
	var walk func(any)
	walk = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if key != "description" {
					walk(child)
				}
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		case string:
			result = append(result, validFileSubstitutions(value)...)
		}
	}
	walk(config)
	sort.Strings(result)
	return result
}

func validFileSubstitutions(content string) []string {
	const marker = "{file:"
	var result []string
	for start := 0; ; {
		i := strings.Index(content[start:], marker)
		if i < 0 {
			return result
		}
		i += start
		end := strings.IndexByte(content[i+len(marker):], '}')
		if end >= 0 {
			reference := strings.TrimSpace(content[i+len(marker) : i+len(marker)+end])
			if reference != "" && !strings.HasPrefix(reference, "~") && !path.IsAbs(reference) {
				clean := path.Clean(slashPath(reference))
				if clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") {
					result = append(result, clean)
				}
			}
		}
		start = i + len(marker)
	}
}
