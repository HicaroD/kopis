package kopis

import (
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

func workflowAction(content, action string) bool {
	return len(workflowSteps(content, action)) != 0
}

func workflowSteps(content, action string) []*yaml.Node {
	var root yaml.Node
	if yaml.Unmarshal([]byte(content), &root) != nil || len(root.Content) == 0 {
		return nil
	}
	jobs := yamlField(root.Content[0], "jobs")
	var matches []*yaml.Node
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		steps := yamlField(jobs.Content[i], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			uses := yamlField(step, "uses")
			if uses != nil && uses.Kind == yaml.ScalarNode && strings.HasPrefix(strings.ToLower(uses.Value), action+"@") {
				matches = append(matches, step)
			}
		}
	}
	return matches
}

func yamlField(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func inspectWorkflow(candidate Candidate) []Finding {
	action := "openai/codex-action"
	if candidate.CatalogRule == "opencode.workflow" {
		action = "anomalyco/opencode/github"
	}
	var findings []Finding
	steps := workflowSteps(candidate.Content, action)
	if len(steps) == 0 {
		return nil
	}
	for _, step := range steps {
		for _, field := range []string{"with", "env"} {
			findings = append(findings, inspectYAMLFields(candidate, yamlField(step, field))...)
		}
	}
	var root yaml.Node
	if yaml.Unmarshal([]byte(candidate.Content), &root) == nil && len(root.Content) > 0 {
		findings = append(findings, inspectYAMLFields(candidate, yamlField(root.Content[0], "env"))...)
		if jobs := yamlField(root.Content[0], "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
			for i := 1; i < len(jobs.Content); i += 2 {
				findings = append(findings, inspectYAMLFields(candidate, yamlField(jobs.Content[i], "env"))...)
			}
		}
	}
	return findings
}

func inspectYAMLFields(candidate Candidate, values *yaml.Node) []Finding {
	if values == nil || values.Kind != yaml.MappingNode {
		return nil
	}
	var findings []Finding
	for i := 0; i+1 < len(values.Content); i += 2 {
		key, value := values.Content[i].Value, values.Content[i+1]
		if value.Kind != yaml.ScalarNode || !credentialAssignmentKey(key) || !literal(value.Value) || excluded(value.Value) {
			continue
		}
		if start := yamlValueOffset(candidate.Content, value); start >= 0 {
			findings = append(findings, finding(candidate, indicatorForKey(strings.ToLower(key)), ClassificationConfirmed, SeverityHigh, value.Value, start, confirmedCredentialGuidance))
		}
	}
	return findings
}

func yamlValueOffset(source string, node *yaml.Node) int {
	start := 0
	for i := 1; i < node.Line; i++ {
		end := strings.IndexByte(source[start:], '\n')
		if end < 0 {
			return -1
		}
		start += end + 1
	}
	start += node.Column - 1
	if start >= len(source) {
		return -1
	}
	// The decoded scalar may have YAML quoting or escapes. Only use a source
	// span that actually contains the decoded credential unchanged.
	lineEnd := strings.IndexByte(source[start:], '\n')
	if lineEnd < 0 {
		lineEnd = len(source) - start
	}
	index := strings.Index(source[start:start+lineEnd], node.Value)
	if index < 0 {
		return -1
	}
	return start + index
}

func inspectTOML(candidate Candidate) []Finding {
	if _, err := toml.Decode(candidate.Content, &map[string]any{}); err != nil {
		return nil
	}
	if candidate.CatalogRule == "gemini.commands" {
		return nil // prompt and description are prose, not credential fields
	}
	var findings []Finding
	section, offset := "", 0
	for _, line := range strings.SplitAfter(candidate.Content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.Trim(trimmed, "[]")
		} else if !strings.HasPrefix(trimmed, "#") {
			if matches := assignment.FindStringSubmatchIndex(line); matches != nil {
				key := line[matches[2]:matches[3]]
				start, end := assignmentValue(matches)
				value := line[start:end]
				if !strings.EqualFold(key, "env_key") && credentialAssignmentKey(key) && literal(value) && !excluded(value) && (section == "" || strings.HasSuffix(section, ".env") || strings.Contains(section, "provider")) {
					findings = append(findings, finding(candidate, indicatorForKey(strings.ToLower(key)), ClassificationConfirmed, SeverityHigh, value, offset+start, confirmedCredentialGuidance))
				}
			}
		}
		offset += len(line)
	}
	return findings
}

func inspectDotenv(candidate Candidate) []Finding {
	var findings []Finding
	offset := 0
	for _, line := range strings.SplitAfter(candidate.Content, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "export ") {
			trimmed = strings.TrimPrefix(trimmed, "export ")
		}
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "\n") {
			offset += len(line)
			continue
		}
		start := len(line) - len(trimmed)
		if match := assignment.FindStringSubmatchIndex(trimmed); match != nil && match[0] == 0 {
			key := trimmed[match[2]:match[3]]
			valueStart, valueEnd := assignmentValue(match)
			value := trimmed[valueStart:valueEnd]
			if credentialAssignmentKey(key) && literal(value) && !excluded(value) {
				findings = append(findings, finding(candidate, indicatorForKey(strings.ToLower(key)), ClassificationConfirmed, SeverityHigh, value, offset+start+valueStart, confirmedCredentialGuidance))
			}
		}
		offset += len(line)
	}
	return findings
}
