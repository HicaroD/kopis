package kopis

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
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

// WriteTerminal writes concise human-readable output. Sensitive content is
// intentionally absent; guidance remains available on finding lines.
func WriteTerminal(w io.Writer, result ScanResult) error {
	presentation := Present(result)
	if _, err := fmt.Fprintf(w, "complete=%t exit_code=%d\n", presentation.Complete, presentation.ExitCode); err != nil {
		return err
	}
	for _, repository := range presentation.Repositories {
		if _, err := fmt.Fprintf(w, "%s %s url=%s status=%s findings=%d\n", repository.Provider, repository.Repository, repository.URL, repository.Status, repository.Findings); err != nil {
			return err
		}
	}
	for _, finding := range presentation.Findings {
		if _, err := fmt.Fprintf(w, "finding provider=%s repository=%s url=%s revision=%s path=%s tool=%s rule=%s location=%d-%d/%d-%d indicator=%s classification=%s severity=%s (%s %s) fingerprint=%s reason=%s\n", finding.Provider, finding.Repository, finding.RepositoryURL, finding.Revision, finding.Path, finding.Tool, finding.CatalogRule, finding.Location.StartLine, finding.Location.StartByte, finding.Location.EndLine, finding.Location.EndByte, finding.Indicator, finding.Classification, finding.Severity, finding.Classification, finding.Severity, finding.Fingerprint, finding.Reason); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "guidance: %s\n", finding.Guidance); err != nil {
			return err
		}
	}
	return nil
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
