package kopis

import (
	"encoding/json"
	"io"
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
	decoder := json.NewDecoder(strings.NewReader(source))
	var findings []Finding
	if err := walkJSONValue(decoder, candidate, "", &findings); err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return findings, true
}

func walkJSONValue(decoder *json.Decoder, candidate Candidate, key string, findings *[]Finding) error {
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
				if err := walkJSONValue(decoder, candidate, name.(string), findings); err != nil {
					return err
				}
			}
		} else if value == '[' {
			for decoder.More() {
				if err := walkJSONValue(decoder, candidate, "", findings); err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	case string:
		if !credentialAssignmentKey(key) || excluded(value) || !literal(value) {
			return nil
		}
		span := candidate.Content[start:int(decoder.InputOffset())]
		quote := strings.IndexByte(span, '"')
		if quote < 0 {
			return nil
		}
		key = strings.ToLower(key)
		severity := SeverityHigh
		if directAuthenticationKey(key) || strings.Contains(key, "private") {
			severity = SeverityCritical
		}
		*findings = append(*findings, findingAt(candidate, indicatorForKey(key), ClassificationConfirmed, severity, value,
			start+quote+1, int(decoder.InputOffset())-1, confirmedCredentialGuidance))
	}
	return nil
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
