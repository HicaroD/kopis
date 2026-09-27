package kopis

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

// Presentation is the redacted, provider-neutral output contract. It contains
// no request token, content excerpt, or matched value.
type Presentation struct {
	Repositories []PresentedRepository `json:"repositories"`
	Findings     []Finding             `json:"findings"`
	Complete     bool                  `json:"complete"`
	ExitCode     int                   `json:"exit_code"`
}

type PresentedRepository struct {
	Provider   string `json:"provider"`
	Repository string `json:"repository"`
	URL        string `json:"url,omitempty"`
	Status     string `json:"status"`
	Findings   int    `json:"findings"`
}

// Present converts scan results into the stable output model used by both
// terminal and JSONL output.
func Present(result ScanResult) Presentation {
	findings := append([]Finding(nil), result.Findings...)
	presentation := Presentation{Findings: findings, Complete: true}
	for i := range presentation.Findings {
		presentation.Findings[i].RepositoryURL = redactURL(presentation.Findings[i].RepositoryURL)
	}
	for _, repository := range result.Repositories {
		if repository.Status == RepositoryPartial || repository.Status == RepositoryUnscanned {
			presentation.Complete = false
		}
		presentation.Repositories = append(presentation.Repositories, PresentedRepository{
			Provider:   repository.Repository.Provider,
			Repository: repository.Repository.ID,
			URL:        redactURL(repository.Repository.URL),
			Status:     repository.Status,
			Findings:   len(repository.Findings),
		})
	}
	if !presentation.Complete {
		presentation.ExitCode = 2
	}
	return presentation
}

// WriteTerminal groups repeated evidence while keeping every source location.
// Sensitive content is intentionally absent.
func WriteTerminal(w io.Writer, result ScanResult) error {
	presentation := Present(result)
	state := "complete"
	if !presentation.Complete {
		state = "incomplete"
	}
	repositoryLabel, findingLabel := "repositories", "findings"
	if len(presentation.Repositories) == 1 {
		repositoryLabel = "repository"
	}
	if len(presentation.Findings) == 1 {
		findingLabel = "finding"
	}
	if _, err := fmt.Fprintf(w, "Scan: %s | %d %s | %d %s\n", state, len(presentation.Repositories), repositoryLabel, len(presentation.Findings), findingLabel); err != nil {
		return err
	}
	for _, repository := range presentation.Repositories {
		if _, err := fmt.Fprintf(w, "\nRepository: %s/%s\n  status: %s | findings: %d\n", repository.Provider, repository.Repository, repository.Status, repository.Findings); err != nil {
			return err
		}
		if repository.URL != "" {
			if _, err := fmt.Fprintf(w, "  url: %s\n", repository.URL); err != nil {
				return err
			}
		}
		for _, group := range groupsForRepository(presentation.Findings, repository) {
			count := "occurrence"
			if len(group.locations) != 1 {
				count = "occurrences"
			}
			if _, err := fmt.Fprintf(w, "\n  %s\n    %s %s %s (%d %s)\n", group.key.path, strings.ToUpper(group.key.severity), group.key.classification, group.key.indicator, len(group.locations), count); err != nil {
				return err
			}
			if group.key.rule != "" || group.key.tool != "" {
				if _, err := fmt.Fprintf(w, "    rule: %s | tool: %s\n", group.key.rule, group.key.tool); err != nil {
					return err
				}
			}
			for _, detail := range []struct{ label, value string }{{"revision", group.key.revision}, {"fingerprint", group.key.fingerprint}, {"reason", group.key.reason}} {
				if detail.value != "" {
					if _, err := fmt.Fprintf(w, "    %s: %s\n", detail.label, detail.value); err != nil {
						return err
					}
				}
			}
			if _, err := fmt.Fprintln(w, "    locations:"); err != nil {
				return err
			}
			for _, location := range group.locations {
				line := fmt.Sprintf("L%d", location.StartLine)
				if location.EndLine != location.StartLine {
					line += fmt.Sprintf("-L%d", location.EndLine)
				}
				if _, err := fmt.Fprintf(w, "      - %s:%d-%d\n", line, location.StartByte, location.EndByte); err != nil {
					return err
				}
			}
			if group.key.guidance != "" {
				if _, err := fmt.Fprintf(w, "    guidance: %s\n", group.key.guidance); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type terminalGroupKey struct {
	path, tool, rule, revision, indicator, classification, severity, fingerprint, reason, guidance string
}

type terminalGroup struct {
	key       terminalGroupKey
	locations []Location
}

func groupsForRepository(findings []Finding, repository PresentedRepository) []terminalGroup {
	indexes := make(map[terminalGroupKey]int)
	var groups []terminalGroup
	for _, finding := range findings {
		if finding.Provider != repository.Provider || finding.Repository != repository.Repository {
			continue
		}
		key := terminalGroupKey{finding.Path, finding.Tool, finding.CatalogRule, finding.Revision, finding.Indicator, finding.Classification, finding.Severity, finding.Fingerprint, finding.Reason, finding.Guidance}
		index, exists := indexes[key]
		if !exists {
			index = len(groups)
			indexes[key] = index
			groups = append(groups, terminalGroup{key: key})
		}
		groups[index].locations = append(groups[index].locations, finding.Location)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].key.path != groups[j].key.path {
			return groups[i].key.path < groups[j].key.path
		}
		return groups[i].key.indicator < groups[j].key.indicator
	})
	for i := range groups {
		sort.Slice(groups[i].locations, func(a, b int) bool {
			left, right := groups[i].locations[a], groups[i].locations[b]
			if left.StartLine != right.StartLine {
				return left.StartLine < right.StartLine
			}
			return left.StartByte < right.StartByte
		})
	}
	return groups
}

// WriteJSONL writes one JSON Lines record containing the same semantic data as
// terminal output. The record is built from the redacted Finding contract.
func WriteJSONL(w io.Writer, result ScanResult) error {
	encoded, err := json.Marshal(Present(result))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", encoded)
	return err
}

// ExitCode returns the command outcome required by the repository status
// contract: incomplete work is never reported as successful.
func ExitCode(result ScanResult) int { return Present(result).ExitCode }

func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.User == nil {
		return raw
	}
	parsed.User = nil
	return parsed.String()
}
