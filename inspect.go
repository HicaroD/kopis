package kopis

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	ClassificationConfirmed      = "confirmed"
	ClassificationReviewRequired = "review_required"
	SeverityCritical             = "critical"
	SeverityHigh                 = "high"
	SeverityMedium               = "medium"
)

// Candidate is the provider-neutral handoff from discovery to inspection.
type Candidate struct {
	Provider, Repository, RepositoryURL, Revision, Path string
	Tool, CatalogRule                                   string
	Content                                             string
}

type Location struct{ StartLine, StartByte, EndLine, EndByte int }

// Finding is deliberately free of matched text and excerpts.
type Finding struct {
	Provider, Repository, RepositoryURL, Revision, Path    string
	Tool, CatalogRule, Indicator, Classification, Severity string
	Fingerprint                                            string
	Location                                               Location
	Guidance                                               string
	Reason                                                 string
}

var (
	assignment   = regexp.MustCompile(`(?im)([A-Za-z][A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|authorization|auth|client[_-]?secret|openai-api-key)[A-Za-z0-9_.-]*)\s*[=:]\s*["']?([^\s"',}\]]+)["']?`)
	quotedSecret = regexp.MustCompile(`(?i)(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}`)
	privateKey   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	secretURL    = regexp.MustCompile(`(?i)https?://[^\s"']+:[^\s@"']+@[^\s"']+`)
	secretFile   = regexp.MustCompile(`(?i)(?:cat|read|open|readFile|fs\.readFileSync)\s+[^\n]*(?:\.env|credentials|secret|token|\.pem)`)
	processArg   = regexp.MustCompile(`(?i)(?:curl|wget|httpie|gh|git|npm|docker)\b[^\n]*(?:--(?:token|password|header|auth)|(?:token|password|authorization)=)`)
	transfer     = regexp.MustCompile(`(?i)(?:curl|wget|scp|rsync|nc|netcat)\b[^\n]*(?:https?://|--data|--upload-file|-T\s)`)
)

// Inspect examines only an already catalogued candidate.
func Inspect(candidate Candidate) []Finding {
	var findings []Finding
	content := candidate.Content
	for _, match := range assignment.FindAllStringSubmatchIndex(content, -1) {
		value := content[match[4]:match[5]]
		if excluded(value) || !literal(value) {
			continue
		}
		key := strings.ToLower(content[match[2]:match[3]])
		indicator := indicatorForKey(key)
		classification := ClassificationConfirmed
		severity := SeverityHigh
		if strings.Contains(key, "private") {
			severity = SeverityCritical
		}
		findings = append(findings, finding(candidate, indicator, classification, severity, value, match[0], "Confirmed literal credential exposure. Rotate or revoke it, remove it from repository history where policy permits, and use runtime secret injection."))
	}
	for _, expression := range []*regexp.Regexp{privateKey, quotedSecret, secretURL} {
		for _, match := range expression.FindAllStringIndex(content, -1) {
			value := content[match[0]:match[1]]
			if excluded(value) {
				continue
			}
			indicator, severity := "private_key", SeverityCritical
			if expression != privateKey {
				indicator, severity = "authorization_value", SeverityHigh
			}
			findings = append(findings, finding(candidate, indicator, ClassificationConfirmed, severity, value, match[0], "Confirmed literal credential exposure. Rotate or revoke it, remove it from repository history where policy permits, and use runtime secret injection."))
		}
	}
	if isExecutableRule(candidate.CatalogRule) {
		for _, item := range []struct {
			re                *regexp.Regexp
			indicator, reason string
		}{{secretFile, "secret_file_read", "Artifact reads a secret-bearing file without establishing literal exposure."}, {processArg, "credential_process_argument", "Artifact passes a credential-bearing argument to a process."}, {transfer, "outbound_transfer", "Artifact contains an outbound transfer command that may transmit sensitive material."}} {
			for _, match := range item.re.FindAllStringIndex(content, -1) {
				findings = append(findings, finding(candidate, item.indicator, ClassificationReviewRequired, SeverityMedium, content[match[0]:match[1]], match[0], "Investigate this behavior before treating it as credential exposure."))
			}
		}
	}
	return uniqueFindings(findings)
}

// InspectCandidate is the named entry point for the inspection boundary.
func InspectCandidate(candidate Candidate) []Finding { return Inspect(candidate) }

func uniqueFindings(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Path + ":" + strconv.Itoa(finding.Location.StartByte) + ":" + strconv.Itoa(finding.Location.EndByte)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, finding)
	}
	return result
}

func finding(c Candidate, indicator, classification, severity, value string, offset int, guidance string) Finding {
	fingerprintValue := ""
	if classification == ClassificationConfirmed {
		fingerprintValue = fingerprint(value)
	}
	return Finding{Provider: c.Provider, Repository: c.Repository, RepositoryURL: safeURL(c.RepositoryURL), Revision: c.Revision, Path: c.Path, Tool: c.Tool, CatalogRule: c.CatalogRule, Indicator: indicator, Classification: classification, Severity: severity, Fingerprint: fingerprintValue, Location: location(c.Content, offset, offset+len(value)), Guidance: guidance, Reason: reasonFor(classification)}
}

func isExecutableRule(rule string) bool {
	return strings.Contains(rule, "plugin") || strings.Contains(rule, "tool") || strings.Contains(rule, "workflow") || strings.Contains(rule, "hooks") || strings.Contains(rule, "skills") || strings.Contains(rule, "rules") || strings.Contains(rule, "commands") || strings.Contains(rule, "assets")
}
func indicatorForKey(key string) string {
	switch {
	case strings.Contains(key, "password"):
		return "password"
	case strings.Contains(key, "client") && strings.Contains(key, "secret"):
		return "oauth_client_secret"
	case strings.Contains(key, "authorization") || strings.Contains(key, "auth"):
		return "authorization_value"
	case strings.Contains(key, "token"):
		return "access_token"
	default:
		return "api_key"
	}
}
func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func literal(value string) bool {
	return len(value) >= 8 && !strings.HasPrefix(value, "$") && !strings.HasPrefix(value, "%") && !strings.Contains(value, "{{")
}
func excluded(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "example") || strings.Contains(lower, "placeholder") || strings.Contains(lower, "redacted") || strings.Contains(lower, "xxxxx") || strings.Contains(lower, "your_") || strings.Contains(lower, "your-") || strings.Contains(lower, "<token>")
}
func reasonFor(classification string) string {
	if classification == ClassificationReviewRequired {
		return "suspicious execution behavior without established literal credential exposure"
	}
	return "literal credential in a catalogued inspection boundary"
}
func safeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}
func location(content string, start, end int) Location {
	line := 1
	for i := 0; i < start && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	endLine := line
	for i := start; i < end && i < len(content); i++ {
		if content[i] == '\n' {
			endLine++
		}
	}
	return Location{StartLine: line, StartByte: start, EndLine: endLine, EndByte: end}
}
