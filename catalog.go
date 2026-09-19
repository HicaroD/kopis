package kopis

import (
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

// RecognizeArtifact applies the catalog to one repository path.
func RecognizeArtifact(filename string, files map[string]string) []Artifact {
	return catalogMatches(filename, files[filename], files)
}

func catalogMatches(filename, content string, files map[string]string) []Artifact {
	p := slashPath(filename)
	var rules []CatalogRule
	switch {
	case p == "opencode.json" || p == "opencode.jsonc":
		rules = append(rules, rule("opencode.config", ToolOpenCode, "project-root opencode configuration", "credential_fields"))
	case strings.HasPrefix(p, ".opencode/plugins/") && hasExtension(p, ".js", ".jsx", ".ts", ".tsx"):
		rules = append(rules, rule("opencode.plugin", ToolOpenCode, "OpenCode plugin", "executable"))
	case strings.HasPrefix(p, ".opencode/tools/"):
		rules = append(rules, rule("opencode.tool", ToolOpenCode, "OpenCode custom tool", "executable"))
	case strings.HasPrefix(p, ".github/workflows/") && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) && strings.Contains(content, "anomalyco/opencode/github"):
		rules = append(rules, rule("opencode.workflow", ToolOpenCode, "workflow using anomalyco/opencode/github", "workflow_provider_key"))
	case p == ".mcp.json":
		rules = append(rules, rule("claude.mcp", ToolClaudeCode, "project-root Claude MCP configuration", "credential_fields"))
	case p == ".claude/settings.json":
		rules = append(rules, rule("claude.settings", ToolClaudeCode, "Claude project settings", "credential_fields"))
	case path.Base(p) == ".mcp.json" && claudePluginRootExists(p, files):
		rules = append(rules, rule("claude.plugin-mcp", ToolClaudeCode, "Claude plugin MCP configuration", "credential_fields"))
	case strings.HasSuffix(p, "/.codex/config.toml") || p == ".codex/config.toml":
		rules = append(rules, rule("codex.config", ToolCodex, "Codex configuration", "credential_fields"))
	case strings.HasPrefix(p, ".github/workflows/") && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) && strings.Contains(content, "openai/codex-action"):
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
	// OpenCode project substitutions admit only the explicitly referenced file.
	if p == "opencode.json" || p == "opencode.jsonc" {
		for _, referenced := range fileSubstitutions(content) {
			if value, ok := files[referenced]; ok {
				_ = value
				rules = append(rules, rule("opencode.file-substitution", ToolOpenCode, "repository-relative {file:...} target", "credential_fields"))
			}
		}
	}
	result := make([]Artifact, 0, len(rules))
	for _, r := range rules {
		result = append(result, Artifact{Path: filename, Rule: r})
	}
	if p == "opencode.json" || p == "opencode.jsonc" {
		for _, referenced := range fileSubstitutions(content) {
			if _, ok := files[referenced]; ok {
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
	return strings.Contains("/"+slashPath(p), "/plugins/")
}

func rule(id, tool, pattern, indicator string) CatalogRule {
	return CatalogRule{ID: id, Tool: tool, Pattern: pattern, Indicators: []string{indicator}, Applicability: "initial evidence-backed catalog", Confidence: "catalogued artifact only"}
}

func slashPath(s string) string { return strings.TrimPrefix(strings.ReplaceAll(s, "\\", "/"), "./") }

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
			result = append(result, slashPath(content[i+len(marker):i+len(marker)+end]))
		}
		start = i + len(marker)
	}
}
