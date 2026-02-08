package output

import (
	"fmt"

	"domeye/internal/analyzer"
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
			fmt.Println()
		}
	}
}
