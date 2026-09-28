package kopis

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type journeyProvider struct {
	provider string
}

func (p journeyProvider) Discover(context.Context, string) ([]Repository, error) {
	return []Repository{
		{Provider: p.provider, ID: "complete/repository", Owner: true, Accessible: true},
		{Provider: p.provider, ID: "partial/repository", Member: true, Accessible: true},
		{Provider: p.provider, ID: "denied/repository", Collaborator: true, Accessible: false},
		{Provider: p.provider, ID: "public-only/repository", Public: true, Accessible: true},
	}, nil
}

func (p journeyProvider) ListFiles(_ context.Context, _ string, repository Repository) FileListing {
	switch repository.ID {
	case "complete/repository":
		return FileListing{Complete: true, Files: []RepositoryFile{{Path: "opencode.json", Revision: "pinned"}}}
	case "partial/repository":
		return FileListing{Complete: false}
	default:
		return FileListing{Complete: true}
	}
}

func (p journeyProvider) FetchFile(context.Context, string, Repository, RepositoryFile) FileOutcome {
	return FileOutcome{Complete: true, Content: "provider_api_key=literal-secret"}
}

func TestDeterministicProviderJourneysReachRedactedOutputs(t *testing.T) {
	for _, provider := range []string{GitHubProvider, GitLabProvider} {
		t.Run(provider, func(t *testing.T) {
			result, err := Scan(context.Background(), ScanRequest{
				Provider:    provider,
				Token:       "runtime-token",
				Scope:       Scope{Kind: ScopeList, RepositoryIDs: []string{"complete/repository", "partial/repository", "denied/repository"}},
				Catalog:     []Artifact{{Path: "opencode.json", Rule: CatalogRule{ID: "opencode.config", Tool: ToolOpenCode}}},
				Scanner:     journeyProvider{provider: provider},
				Concurrency: 2,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Repositories) != 3 || len(result.Findings) != 1 {
				t.Fatalf("unexpected journey result: %+v", result)
			}
			statuses := map[string]bool{}
			for _, repository := range result.Repositories {
				statuses[repository.Status] = true
			}
			for _, status := range []string{RepositoryFindings, RepositoryPartial, RepositoryUnscanned} {
				if !statuses[status] {
					t.Fatalf("missing status %q: %+v", status, statuses)
				}
			}
			var terminal, jsonl bytes.Buffer
			if err := WriteTerminal(&terminal, result); err != nil {
				t.Fatal(err)
			}
			if err := WriteJSONL(&jsonl, result); err != nil {
				t.Fatal(err)
			}
			if ExitCode(result) == 0 || strings.Contains(terminal.String(), "literal-secret") || strings.Contains(jsonl.String(), "literal-secret") || strings.Contains(jsonl.String(), "runtime-token") {
				t.Fatalf("protected data or successful incomplete outcome crossed boundary: terminal=%q jsonl=%q", terminal.String(), jsonl.String())
			}
			var presentation Presentation
			if err := json.Unmarshal(jsonl.Bytes(), &presentation); err != nil || len(presentation.Findings) != 1 || presentation.Findings[0].Reason == "" {
				t.Fatalf("JSONL omitted finding semantics: %s %+v", err, presentation)
			}
		})
	}
}

func TestCatalogSubstitutionAndClaudeMarkerBoundaries(t *testing.T) {
	files := map[string]string{
		"opencode.json":               `{"instructions":["{file:secrets.txt}"]}`,
		"secrets.txt":                 "api_key=literal-secret",
		"plugins/unrelated/.mcp.json": "token=literal-secret",
	}
	opencode := RecognizeArtifact("opencode.json", files)
	if len(opencode) != 2 || opencode[0].Rule.ID != "opencode.config" || opencode[1].Rule.ID != "opencode.file-substitution" {
		t.Fatalf("config inherited target substitution rule: %+v", opencode)
	}
	if got := RecognizeArtifact("plugins/unrelated/.mcp.json", files); len(got) != 0 {
		t.Fatalf("unmarked Claude plugin was admitted: %+v", got)
	}
	files["plugins/unrelated/.claude-plugin/plugin.json"] = "{}"
	if got := RecognizeArtifact("plugins/unrelated/.mcp.json", files); len(got) != 1 || got[0].Rule.ID != "claude.plugin-mcp" {
		t.Fatalf("marker-backed Claude plugin was not admitted: %+v", got)
	}
}

func TestInspectionCredentialFormsLocationsSeverityAndExecution(t *testing.T) {
	content := "api_key=literal-api-value\npassword: literal-password\nclientSecret=literal-client-secret\n" +
		"authorization=Bearer literal-auth-value\n" +
		"api_key_default=${TOKEN:-literal-default}\nref=${TOKEN}\nplain=$TOKEN\npercent=%TOKEN%\n" +
		"fs.readFileSync(\".env\")\nreadFile(\"credentials\")\nopen(\"key.pem\")"
	findings := Inspect(Candidate{Path: "plugin.ts", CatalogRule: "opencode.plugin", Content: content})
	if len(findings) != 8 {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Location.StartByte < 0 || finding.Location.EndByte <= finding.Location.StartByte || finding.Location.StartLine < 1 {
			t.Fatalf("invalid value location: %+v", finding)
		}
		if finding.Classification == ClassificationConfirmed && finding.Fingerprint == "" {
			t.Fatalf("confirmed finding lacks fingerprint: %+v", finding)
		}
	}
	critical := 0
	medium := 0
	for _, finding := range findings {
		if finding.Severity == SeverityCritical {
			critical++
		}
		if finding.Severity == SeverityMedium {
			medium++
		}
	}
	if critical != 4 || medium != 3 {
		t.Fatalf("unexpected severity mapping: %+v", findings)
	}
}

func TestInspectionDetectsNestedJSONCredentialAtValueLocation(t *testing.T) {
	content := "{\"mcpServers\":{\"provider\":{\"api_key\":\"synthetic-secret-123\",\"env\":{\"access_token\":\"${TOKEN}\"}}}}"
	findings := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content})
	if len(findings) != 1 || findings[0].Indicator != "api_key" || findings[0].Classification != ClassificationConfirmed {
		t.Fatalf("nested JSON credential was not identified: %+v", findings)
	}
	f := findings[0]
	if got := content[f.Location.StartByte:f.Location.EndByte]; got != "synthetic-secret-123" {
		t.Fatalf("incorrect JSON source span: %q", got)
	}
}

func TestInspectionJSONCTracksEscapedValuesAndIgnoresExampleText(t *testing.T) {
	content := "// sample settings\n{\n  \"description\": \"api_key=synthetic-decoy-123\",\n  \"credentials\": {\n    \"api_key\": \"synthetic\\u002dvalue-456\" // attached comment\n  }\n}"
	findings := Inspect(Candidate{Path: "opencode.jsonc", CatalogRule: "opencode.config", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-value-456") {
		t.Fatalf("JSONC value was lost or description reported: %+v", findings)
	}
	f := findings[0]
	if got := content[f.Location.StartByte:f.Location.EndByte]; got != `synthetic\u002dvalue-456` {
		t.Fatalf("escaped value lost its source span: %q", got)
	}
}

func TestInspectionJSONCAllowsTrailingCommas(t *testing.T) {
	content := `{"config":{"api_key":"synthetic-value-789",},}`
	findings := Inspect(Candidate{Path: "opencode.jsonc", CatalogRule: "opencode.config", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-value-789") {
		t.Fatalf("trailing comma prevented structured inspection: %+v", findings)
	}
}

func TestInspectionDoesNotSilentlyIgnoreLiteralContainingExample(t *testing.T) {
	content := `{"api_key":"synthetic-example-value-456","fallback":"placeholder"}`
	findings := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-example-value-456") {
		t.Fatalf("ordinary substring falsely excluded a credential-shaped value: %+v", findings)
	}
}

func TestInspectionOpenCodeEnvReferencesAreNotLiteralCredentials(t *testing.T) {
	content := `{"mcp":{"remote":{"headers":{"x-personal-token":"{env:PERSONAL_TOKEN}","Authorization":"Bearer {env:REMOTE_API_KEY}"}},"other":{"headers":{"Authorization":"Bearer synthetic-literal-token-123"}}}}`
	findings := Inspect(Candidate{Path: "opencode.json", CatalogRule: "opencode.config", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("Bearer synthetic-literal-token-123") {
		t.Fatalf("OpenCode environment references were treated as exposed literals, or a literal was lost: %+v", findings)
	}
}

func TestInspectionQuotedDefaultUsesLiteralLocationAndFingerprint(t *testing.T) {
	content := `api_key="${TOKEN:-literal-secret}" api_key=${TOKEN:-literal-secret}`
	findings := Inspect(Candidate{Path: "opencode.json", CatalogRule: "opencode.config", Content: content})
	if len(findings) != 2 {
		t.Fatalf("expected both quoted and unquoted defaults: %+v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != SeverityCritical || finding.Fingerprint != fingerprint("literal-secret") {
			t.Fatalf("default was not treated as the confirmed literal: %+v", finding)
		}
		if got := content[finding.Location.StartByte:finding.Location.EndByte]; got != "literal-secret" {
			t.Fatalf("default location included expression syntax: %q", got)
		}
	}
}

func TestInspectionCredentialURLIsHighUnlessDirectField(t *testing.T) {
	findings := Inspect(Candidate{Path: "settings.json", CatalogRule: "claude.settings", Content: `url="https://user:password@safe.test/path"`})
	if len(findings) != 1 || findings[0].Indicator != "authorization_value" || findings[0].Severity != SeverityHigh {
		t.Fatalf("credential-bearing URL was over-promoted: %+v", findings)
	}
}

func TestInspectionFindsJSONEscapedShellPasswordWithoutExposingIt(t *testing.T) {
	content := `{"permissions":{"allow":["Bash(PGPASSWORD=\"synthetic-db-pass-123\" psql:*)"]}}`
	findings := Inspect(Candidate{Path: ".claude/settings.json", CatalogRule: "claude.settings", Content: content})
	if len(findings) != 1 || findings[0].Indicator != "password" || findings[0].Classification != ClassificationConfirmed {
		t.Fatalf("escaped shell assignment not recognized: count=%d", len(findings))
	}
	finding := findings[0]
	if content[finding.Location.StartByte:finding.Location.EndByte] != "synthetic-db-pass-123" || finding.Fingerprint != fingerprint("synthetic-db-pass-123") {
		t.Fatal("escaped assignment has an incorrect source location or fingerprint")
	}
	encoded, err := json.Marshal(findings)
	if err != nil || strings.Contains(string(encoded), "synthetic-db-pass-123") {
		t.Fatal("credential leaked into finding output")
	}
}

func TestInspectionFindsDatabaseURLPasswordAndRejectsPlaceholders(t *testing.T) {
	content := `{"allow":["Bash(DATABASE_URL=\"postgresql://account:synthetic-db-pass-456@db.test:5432/app\" psql:*)", "Bash(DATABASE_URL=\"postgresql://account:${DB_PASSWORD}@db.test/app\" psql:*)"]}`
	findings := Inspect(Candidate{Path: ".claude/settings.json", CatalogRule: "claude.settings", Content: content})
	if len(findings) != 1 || findings[0].Indicator != "password" || findings[0].Severity != SeverityHigh {
		t.Fatalf("database URL password not distinguished from placeholder: count=%d", len(findings))
	}
	if content[findings[0].Location.StartByte:findings[0].Location.EndByte] != "synthetic-db-pass-456" || findings[0].Fingerprint != fingerprint("synthetic-db-pass-456") {
		t.Fatal("database URL password has an incorrect source location or fingerprint")
	}
}

func TestInspectionDoesNotTreatCaptionTokensAsAccessTokens(t *testing.T) {
	content := "const SWITCH_CAPTIONS_EVERY_MS = 1200;\n" +
		"createTikTokStyleCaptions({ captions, combineTokensWithinMilliseconds: SWITCH_CAPTIONS_EVERY_MS });\n" +
		"const isActive = token.fromMs <= absoluteTimeMs && token.toMs > absoluteTimeMs;"
	findings := Inspect(Candidate{Path: ".gemini/skills/remotion-best-practices/rules/display-captions.md", CatalogRule: "gemini.skills", Content: content})
	if len(findings) != 0 {
		t.Fatalf("caption timing misclassified as a credential: %+v", findings)
	}
}

func TestInspectionDistinguishesEnvironmentReferenceFromLiteralAccessToken(t *testing.T) {
	content := "const accessToken = process.env.MAPS_ACCESS_TOKEN;\n" +
		"const otherToken = import.meta.env.VITE_API_TOKEN;\n" +
		"const accessToken = 'synthetic-literal-token-123';"
	findings := Inspect(Candidate{Path: ".opencode/tools/maps.ts", CatalogRule: "opencode.tool", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-literal-token-123") || findings[0].Indicator != "access_token" {
		t.Fatalf("environment reference reported or literal token missed: %+v", findings)
	}
}

func TestStructuredConfigIgnoresProseAndReferenceNamesButFindsCredentialValues(t *testing.T) {
	cases := []struct {
		path, rule, content, want string
	}{
		{"opencode.json", "opencode.config", `{"description":"Bearer synthetic-documentation-123","provider":{"sample":{"options":{"apiKey":"{env:KEY}"}},"real":{"options":{"apiKey":"synthetic-live-key-123"}}}}`, "synthetic-live-key-123"},
		{".mcp.json", "claude.mcp", `{"mcpServers":{"demo":{"command":"api_key=synthetic-example-123","env":{"API_KEY":"${API_KEY}"}},"real":{"type":"http","url":"https://example.test","headers":{"Authorization":"Bearer synthetic-live-token-123"}}}}`, "Bearer synthetic-live-token-123"},
		{".claude/settings.json", "claude.settings", `{"permissions":{"deny":["Bash(api_key=synthetic-example-123 *)"],"allow":["Bash(PGPASSWORD=synthetic-live-pass-123 psql:*)"]},"env":{"API_KEY":"${API_KEY}"}}`, "synthetic-live-pass-123"},
		{"gemini-extension.json", "gemini.extension", `{"description":"Bearer synthetic-example-123","settings":[{"envVar":"SYNTHETIC_API_KEY","sensitive":true}],"mcpServers":{"real":{"env":{"API_KEY":"synthetic-live-key-123"}}}}`, "synthetic-live-key-123"},
	}
	for _, tc := range cases {
		t.Run(tc.rule, func(t *testing.T) {
			findings := Inspect(Candidate{Path: tc.path, CatalogRule: tc.rule, Content: tc.content})
			if len(findings) != 1 || findings[0].Fingerprint != fingerprint(tc.want) {
				t.Fatalf("expected only credential-bearing value: %+v", findings)
			}
		})
	}
}

func TestMalformedStructuredConfigDoesNotBecomeConfirmedAssignment(t *testing.T) {
	findings := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: `{"description":"api_key=synthetic-example-123",`})
	if len(findings) != 0 {
		t.Fatalf("invalid JSON became a confirmed credential: %+v", findings)
	}
}

func TestJSONCSubstitutionOnlyFollowsActualValuesAndContainedPaths(t *testing.T) {
	files := map[string]string{
		"opencode.jsonc": `// {file:decoy.txt}
{"instructions":["{file:./included.txt}","{file:../outside.txt}","{file:/absolute.txt}"],"description":"{file:decoy.txt}"}`,
		"included.txt": "api_key=synthetic-value-123", "decoy.txt": "", "../outside.txt": "", "/absolute.txt": "",
	}
	artifacts := RecognizeArtifact("opencode.jsonc", files)
	if len(artifacts) != 2 || artifacts[1].Path != "included.txt" {
		t.Fatalf("followed a comment, prose, or out-of-repository reference: %+v", artifacts)
	}
}

func TestCredentialKeyDoesNotMatchUnrelatedWords(t *testing.T) {
	findings := Inspect(Candidate{Path: ".codex/config.toml", CatalogRule: "codex.config", Content: "author = 'synthetic-person-123'\nauth_token = 'synthetic-token-123'\n"})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-token-123") {
		t.Fatalf("word fragment was treated as an auth key: %+v", findings)
	}
}

func TestWorkflowRequiresActionStepAndInspectsOnlyCredentialInputs(t *testing.T) {
	path := ".github/workflows/ai.yml"
	comment := "# uses: openai/codex-action@v1\nname: demo\njobs: {test: {runs-on: ubuntu-latest, steps: [{run: 'api_key=synthetic-example-123'}]}}\n"
	if got := RecognizeArtifact(path, map[string]string{path: comment}); len(got) != 0 {
		t.Fatalf("workflow action in a comment was admitted: %+v", got)
	}
	content := `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          prompt: 'api_key=synthetic-example-123'
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
      - uses: openai/codex-action@v1
        with:
          openai-api-key: synthetic-live-key-123
`
	if got := RecognizeArtifact(path, map[string]string{path: content}); len(got) != 1 || got[0].Rule.ID != "codex.workflow" {
		t.Fatalf("actual workflow action not admitted: %+v", got)
	}
	findings := Inspect(Candidate{Path: path, CatalogRule: "codex.workflow", Content: content})
	if len(findings) != 1 || findings[0].Fingerprint != fingerprint("synthetic-live-key-123") {
		t.Fatalf("workflow prompt or secret reference reported, or literal missed: %+v", findings)
	}
}

func TestTOMLCommandsAndProviderNamesDoNotBecomeCredentials(t *testing.T) {
	command := "description = 'api_key=synthetic-example-123'\nprompt = '''Use token=synthetic-example-456 in a sample.'''\n"
	if got := Inspect(Candidate{Path: ".gemini/commands/help.toml", CatalogRule: "gemini.commands", Content: command}); len(got) != 0 {
		t.Fatalf("prompt prose reported as credential: %+v", got)
	}
	config := "[model_providers.example]\nenv_key = 'SYNTHETIC_API_KEY'\n[model_providers.example.env]\nAPI_KEY = 'synthetic-live-key-123'\n"
	got := Inspect(Candidate{Path: ".codex/config.toml", CatalogRule: "codex.config", Content: config})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-live-key-123") {
		t.Fatalf("provider variable name reported or env literal missed: %+v", got)
	}
}

func TestExtensionDotenvDistinguishesCommentsReferencesAndLiterals(t *testing.T) {
	content := "# API_KEY=synthetic-example-123\nAPI_KEY=${API_KEY}\nexport ACCESS_TOKEN='synthetic-live-token-123' # inline\n"
	got := Inspect(Candidate{Path: "extension/.env", CatalogRule: "gemini.extension-env", Content: content})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-live-token-123") {
		t.Fatalf("dotenv comment or reference reported, or literal missed: %+v", got)
	}
}

func TestSkillProseAndToolDocumentationAreNotExecutableCredentials(t *testing.T) {
	content := "# Example\n```sh\napi_key=synthetic-example-123\ncurl https://example.test\n```\n"
	for _, tc := range []struct{ path, rule string }{
		{".agents/skills/demo/SKILL.md", "gemini.skills"},
		{".agents/rules/demo.md", "antigravity.rules"},
		{".opencode/tools/README.md", "opencode.tool"},
		{"extension/skills/demo/SKILL.md", "gemini.extension-assets"},
	} {
		if findings := Inspect(Candidate{Path: tc.path, CatalogRule: tc.rule, Content: content}); len(findings) != 0 {
			t.Errorf("%s prose reported as executable exposure: %+v", tc.path, findings)
		}
	}
}

func TestJSONRemoteURLDetectsPasswordButNotDocumentationURL(t *testing.T) {
	content := `{"description":"https://sample:example-password@example.test/docs","mcpServers":{"remote":{"type":"http","url":"https://user:synthetic-live-pass-123@mcp.test/api"}}}`
	got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-live-pass-123") {
		t.Fatalf("MCP URL password missed or description URL reported: %+v", got)
	}
}

func TestPluginCommentsAreNotCredentialsOrExecutableBehavior(t *testing.T) {
	content := "// api_key=synthetic-example-123\n/* curl https://example.test with token=synthetic-example-456 */\n" +
		"const endpoint = 'https://example.test';\nconst apiKey = 'synthetic-live-key-123';\n"
	got := Inspect(Candidate{Path: ".opencode/plugins/custom.ts", CatalogRule: "opencode.plugin", Content: content})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-live-key-123") {
		t.Fatalf("plugin comments reported or literal missed: %+v", got)
	}
}

func TestStructuredInterpolatedHeaderIsNotConfirmedLiteral(t *testing.T) {
	content := `{"mcpServers":{"remote":{"type":"http","url":"https://mcp.test","headers":{"Authorization":"Bearer ${API_TOKEN}"}}}}`
	if got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content}); len(got) != 0 {
		t.Fatalf("runtime interpolation treated as committed credential: %+v", got)
	}
}

func TestWorkflowJobEnvironmentCredentialIsInspected(t *testing.T) {
	content := `jobs:
  test:
    runs-on: ubuntu-latest
    env:
      API_KEY: synthetic-job-key-123
    steps:
      - uses: anomalyco/opencode/github@v1
        with:
          prompt: 'Explain API_KEY=synthetic-example-123'
`
	got := Inspect(Candidate{Path: ".github/workflows/opencode.yaml", CatalogRule: "opencode.workflow", Content: content})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-job-key-123") {
		t.Fatalf("job environment literal missed or prompt reported: %+v", got)
	}
}

func TestOpenCodeToolDirectoryOnlyAdmitsToolModules(t *testing.T) {
	files := map[string]string{".opencode/tools/README.md": "api_key=synthetic-example-123", ".opencode/tools/deploy.ts": "export default {}"}
	if got := RecognizeArtifact(".opencode/tools/README.md", files); len(got) != 0 {
		t.Fatalf("documentation was admitted as a custom tool: %+v", got)
	}
	if got := RecognizeArtifact(".opencode/tools/deploy.ts", files); len(got) != 1 || got[0].Rule.ID != "opencode.tool" {
		t.Fatalf("custom tool module was missed: %+v", got)
	}
}

func TestMCPServerArgsDatabasePasswordIsNotLost(t *testing.T) {
	content := `{"mcpServers":{"remote":{"command":"npx","args":["server","postgresql://user:synthetic-db-pass-123@db.example.test:5432/app"]}}}`
	got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-db-pass-123") || got[0].Indicator != "password" {
		t.Fatalf("literal password in MCP args missed: %+v", got)
	}
}

func TestLoopbackDatabaseCredentialsAreNotConfirmedExposures(t *testing.T) {
	for _, address := range []string{"localhost:8432", "127.0.0.1:5432", "[::1]:5432"} {
		content := `{"mcpServers":{"local":{"command":"npx","args":["postgresql://user:synthetic-dev-pass-123@` + address + `/app"]}}}`
		if got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content}); len(got) != 0 {
			t.Errorf("loopback example marked exposed (%s): %+v", address, got)
		}
	}
	remote := `{"mcpServers":{"remote":{"args":["postgresql://user:synthetic-real-pass-123@db.example.test/app"]}}}`
	got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: remote})
	if len(got) != 1 || got[0].Fingerprint != fingerprint("synthetic-real-pass-123") {
		t.Fatalf("non-loopback password missed: %+v", got)
	}
}

func TestLoopbackSuppressionAlsoAppliesOutsideMCPArgs(t *testing.T) {
	for _, content := range []string{
		`database_url="postgresql://user:synthetic-dev-pass-123@localhost/app"`,
		`endpoint="https://user:synthetic-dev-pass-123@127.0.0.1/api"`,
		`{"mcpServers":{"local":{"type":"http","url":"https://user:synthetic-dev-pass-123@localhost/api"}}}`,
	} {
		if got := Inspect(Candidate{Path: ".mcp.json", CatalogRule: "claude.mcp", Content: content}); len(got) != 0 {
			t.Errorf("loopback URL reported: %+v", got)
		}
	}
}

func TestCatalogExcludesMarkdownButAdmitsAdjacentExecutableAssets(t *testing.T) {
	files := map[string]string{
		"extension/gemini-extension.json":     "{}",
		"extension/skills/demo/SKILL.md":      "api_key=synthetic-example-123",
		"extension/skills/demo/reference.MDX": "api_key=synthetic-example-123",
		"extension/hooks/check.sh":            "api_key=synthetic-live-key-123",
		".agents/skills/demo/SKILL.md":        "",
		".agents/rules/demo.md":               "",
		".gemini/skills/demo/SKILL.md":        "",
	}
	for filename := range files {
		if (strings.HasSuffix(strings.ToLower(filename), ".md") || strings.HasSuffix(strings.ToLower(filename), ".mdx")) && len(RecognizeArtifact(filename, files)) != 0 {
			t.Errorf("Markdown admitted: %s", filename)
		}
	}
	if got := RecognizeArtifact("extension/hooks/check.sh", files); len(got) != 1 || got[0].Rule.ID != "gemini.extension-assets" {
		t.Fatalf("neighboring script lost: %+v", got)
	}
}

func TestDirectInspectionAlsoExcludesMarkdown(t *testing.T) {
	for _, path := range []string{".agents/skills/demo/SKILL.md", "extension/skills/demo/reference.MDX"} {
		if got := Inspect(Candidate{Path: path, CatalogRule: "gemini.skills", Content: "api_key=synthetic-live-key-123"}); len(got) != 0 {
			t.Fatalf("Markdown should not be inspected even as a direct candidate: %s %+v", path, got)
		}
	}
}
