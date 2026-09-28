package kopis

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// inspectJSONCredentials walks configuration values instead of matching text in
// JSON strings. The decoder's input offsets preserve the original source span.
func inspectJSONCredentials(candidate Candidate) ([]Finding, bool) {
	if !strings.HasSuffix(candidate.Path, ".json") && !strings.HasSuffix(candidate.Path, ".jsonc") {
		return nil, false
	}
	source := candidate.Content
	if strings.HasSuffix(candidate.Path, ".jsonc") {
		source = stripJSONComments(source)
	}
	// Preserve inspection of legacy plain-text fixtures and mislabeled files,
	// without treating a broken JSON document as free-form credential text.
	trimmed := strings.TrimSpace(source)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(source))
	var findings []Finding
	if err := walkJSONValue(decoder, candidate, nil, &findings); err != nil {
		return nil, true
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, true
	}
	return findings, true
}

func walkJSONValue(decoder *json.Decoder, candidate Candidate, path []string, findings *[]Finding) error {
	start := int(decoder.InputOffset())
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		if value == '{' {
			for decoder.More() {
				name, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := walkJSONValue(decoder, candidate, append(path[:len(path):len(path)], name.(string)), findings); err != nil {
					return err
				}
			}
		} else if value == '[' {
			for decoder.More() {
				if err := walkJSONValue(decoder, candidate, append(path[:len(path):len(path)], "*"), findings); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	case string:
		span := candidate.Content[start:int(decoder.InputOffset())]
		quote := strings.IndexByte(span, '"')
		if quote < 0 {
			return nil
		}
		valueStart, valueEnd := start+quote+1, int(decoder.InputOffset())-1
		if len(path) >= 4 && path[0] == "mcpServers" && path[len(path)-2] == "args" && path[len(path)-1] == "*" {
			for _, match := range databaseURL.FindAllStringSubmatchIndex(candidate.Content[valueStart:valueEnd], -1) {
				password := candidate.Content[valueStart+match[2] : valueStart+match[3]]
				if literal(password) && !excluded(password) && !localCredentialURL(candidate.Content[valueStart+match[0]:valueStart+match[1]]) {
					*findings = append(*findings, finding(candidate, "password", ClassificationConfirmed, SeverityHigh, password, valueStart+match[2], confirmedCredentialGuidance))
				}
			}
		}
		if len(path) >= 3 && (candidate.CatalogRule == "claude.mcp" || candidate.CatalogRule == "claude.plugin-mcp" || candidate.CatalogRule == "gemini.extension" || candidate.CatalogRule == "gemini.settings") &&
			path[0] == "mcpServers" && path[len(path)-1] == "url" {
			if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
				if password, ok := parsed.User.Password(); ok && literal(password) && !excluded(password) && !localCredentialURL(value) {
					if relative := strings.Index(candidate.Content[valueStart:valueEnd], password); relative >= 0 {
						*findings = append(*findings, finding(candidate, "password", ClassificationConfirmed, SeverityHigh, password, valueStart+relative, confirmedCredentialGuidance))
					}
				}
			}
		}
		if jsonExecutableString(candidate.CatalogRule, path) {
			*findings = append(*findings, inspectEmbeddedCommand(candidate, candidate.Content[valueStart:valueEnd], valueStart)...)
		}
		if !jsonCredentialField(path) || excluded(value) || !literal(value) {
			return nil
		}
		key := path[len(path)-1]
		key = strings.ToLower(key)
		severity := SeverityHigh
		if directAuthenticationKey(key) || strings.Contains(key, "private") {
			severity = SeverityCritical
		}
		*findings = append(*findings, findingAt(candidate, indicatorForKey(key), ClassificationConfirmed, severity, value,
			valueStart, valueEnd, confirmedCredentialGuidance))
	}
	return nil
}

func jsonCredentialField(path []string) bool {
	if len(path) == 0 || !credentialAssignmentKey(path[len(path)-1]) {
		return false
	}
	for _, part := range path[:len(path)-1] {
		switch strings.ToLower(part) {
		case "description", "instructions", "prompt", "template", "permissions", "allow", "deny", "settings", "command", "args", "name":
			return false
		}
	}
	switch strings.ToLower(path[len(path)-1]) {
	case "description", "envvar", "env_key", "name":
		return false
	}
	return true
}

func jsonExecutableString(rule string, path []string) bool {
	if rule == "claude.settings" && len(path) >= 2 && path[len(path)-2] == "allow" && path[len(path)-1] == "*" {
		return true
	}
	return false
}

// Replacing comments with whitespace retains byte positions for JSONC tokens.
func stripJSONComments(source string) string {
	bytes := []byte(source)
	inString, escape := false, false
	for i := 0; i < len(bytes); i++ {
		if inString {
			if escape {
				escape = false
			} else if bytes[i] == '\\' {
				escape = true
			} else if bytes[i] == '"' {
				inString = false
			}
			continue
		}
		if bytes[i] == '"' {
			inString = true
			continue
		}
		if i+1 < len(bytes) && bytes[i] == '/' && bytes[i+1] == '/' {
			for i < len(bytes) && bytes[i] != '\n' {
				bytes[i] = ' '
				i++
			}
			continue
		}
		if i+1 < len(bytes) && bytes[i] == '/' && bytes[i+1] == '*' {
			bytes[i], bytes[i+1] = ' ', ' '
			i += 2
			for i < len(bytes) && !(i+1 < len(bytes) && bytes[i] == '*' && bytes[i+1] == '/') {
				if bytes[i] != '\n' {
					bytes[i] = ' '
				}
				i++
			}
			if i+1 < len(bytes) {
				bytes[i], bytes[i+1] = ' ', ' '
				i++
			}
		}
	}
	inString, escape = false, false
	for i := 0; i < len(bytes); i++ {
		if inString {
			if escape {
				escape = false
			} else if bytes[i] == '\\' {
				escape = true
			} else if bytes[i] == '"' {
				inString = false
			}
			continue
		}
		if bytes[i] == '"' {
			inString = true
		} else if bytes[i] == ',' {
			j := i + 1
			for j < len(bytes) && (bytes[j] == ' ' || bytes[j] == '\t' || bytes[j] == '\r' || bytes[j] == '\n') {
				j++
			}
			if j < len(bytes) && (bytes[j] == '}' || bytes[j] == ']') {
				bytes[i] = ' '
			}
		}
	}
	return string(bytes)
}
