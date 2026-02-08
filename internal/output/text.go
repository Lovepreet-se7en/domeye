package output

import (
	"fmt"

	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

type TextFormatter struct {
}

func (f *TextFormatter) Format(results chan analyzer.Result) {
	for result := range results {
		fmt.Printf("\n=== Scan Results for: %s ===\n", result.URL)

		if len(result.Vulnerabilities) == 0 {
			fmt.Println("No vulnerabilities found!")
			continue
		}

		fmt.Printf("Found %d vulnerabilities:\n\n", len(result.Vulnerabilities))

		for i, vuln := range result.Vulnerabilities {
			fmt.Printf("Vulnerability #%d:\n", i+1)
			fmt.Printf("  Type: %s\n", vuln.Type)
			fmt.Printf("  Severity: %s\n", vuln.Severity)
			fmt.Printf("  Description: %s\n", vuln.Description)
			fmt.Printf("  Location: %s\n", vuln.Location)
			if vuln.Details != "" {
				fmt.Printf("  Details: %s\n", vuln.Details)
			}
			if vuln.ProofOfConcept != "" {
				fmt.Printf("  Proof of Concept: %s\n", vuln.ProofOfConcept)
			}
			if vuln.Confidence != "" {
				fmt.Printf("  Confidence: %s\n", vuln.Confidence)
			}
			if vuln.CVSSScore != "" {
				fmt.Printf("  CVSS Score: %s\n", vuln.CVSSScore)
			}
			if vuln.CWEID != "" {
				fmt.Printf("  CWE ID: %s\n", vuln.CWEID)
			}
			if vuln.Remediation != "" {
				fmt.Printf("  Remediation: %s\n", vuln.Remediation)
			}
			if vuln.SourceSinkPath != "" {
				fmt.Printf("  Source-Sink Path: %s\n", vuln.SourceSinkPath)
			}
			if vuln.CodeSnippet != "" {
				fmt.Printf("  Code Snippet: %s\n", vuln.CodeSnippet)
			}
			if len(vuln.References) > 0 {
				fmt.Printf("  References:\n")
				for _, ref := range vuln.References {
					fmt.Printf("    - %s\n", ref)
				}
			}
			fmt.Println()
		}
	}
}
