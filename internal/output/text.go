package output

import (
	"fmt"
	"io"

	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

type TextFormatter struct {
}

func (f *TextFormatter) Format(results chan analyzer.Result, w io.Writer) {
	for result := range results {
		fmt.Fprintf(w, "\n=== Scan Results for: %s ===\n", result.URL)

		if len(result.Vulnerabilities) == 0 {
			fmt.Fprintln(w, "No vulnerabilities found!")
			continue
		}

		fmt.Fprintf(w, "Found %d vulnerabilities:\n\n", len(result.Vulnerabilities))

		for i, vuln := range result.Vulnerabilities {
			fmt.Fprintf(w, "Vulnerability #%d:\n", i+1)
			fmt.Fprintf(w, "  Type: %s\n", vuln.Type)
			fmt.Fprintf(w, "  Severity: %s\n", vuln.Severity)
			fmt.Fprintf(w, "  Description: %s\n", vuln.Description)
			fmt.Fprintf(w, "  Location: %s\n", vuln.Location)
			if vuln.Details != "" {
				fmt.Fprintf(w, "  Details: %s\n", vuln.Details)
			}
			if vuln.ProofOfConcept != "" {
				fmt.Fprintf(w, "  Proof of Concept: %s\n", vuln.ProofOfConcept)
			}
			if vuln.Confidence != "" {
				fmt.Fprintf(w, "  Confidence: %s\n", vuln.Confidence)
			}
			if vuln.CVSSScore != "" {
				fmt.Fprintf(w, "  CVSS Score: %s\n", vuln.CVSSScore)
			}
			if vuln.CWEID != "" {
				fmt.Fprintf(w, "  CWE ID: %s\n", vuln.CWEID)
			}
			if vuln.Remediation != "" {
				fmt.Fprintf(w, "  Remediation: %s\n", vuln.Remediation)
			}
			if vuln.SourceSinkPath != "" {
				fmt.Fprintf(w, "  Source-Sink Path: %s\n", vuln.SourceSinkPath)
			}
			if vuln.CodeSnippet != "" {
				fmt.Fprintf(w, "  Code Snippet: %s\n", vuln.CodeSnippet)
			}
			if len(vuln.References) > 0 {
				fmt.Fprintf(w, "  References:\n")
				for _, ref := range vuln.References {
					fmt.Fprintf(w, "    - %s\n", ref)
				}
			}
			fmt.Fprintln(w)
		}
	}
}
