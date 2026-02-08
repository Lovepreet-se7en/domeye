package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"domeye/internal/scanner"
)

var xssPatterns = []struct {
	pattern     *regexp.Regexp
	severity    string
	description string
}{
	{
		pattern:     regexp.MustCompile(`(?i)innerHTML\s*=`),
		severity:    "High",
		description: "Potential DOM XSS via innerHTML assignment",
	},
	{
		pattern:     regexp.MustCompile(`(?i)document\.write\s*\(`),
		severity:    "High",
		description: "Potential DOM XSS via document.write",
	},
	{
		pattern:     regexp.MustCompile(`(?i)eval\s*\(`),
		severity:    "Critical",
		description: "Potential DOM XSS via eval function",
	},
	{
		pattern:     regexp.MustCompile(`(?i)location\.href\s*=`),
		severity:    "Medium",
		description: "Potential open redirect via location.href assignment",
	},
	{
		pattern:     regexp.MustCompile(`(?i)location\.hash`),
		severity:    "Medium",
		description: "Potential DOM XSS via location.hash",
	},
	{
		pattern:     regexp.MustCompile(`(?i)URL\s*\.\s*\w+\s*\(`),
		severity:    "Medium",
		description: "Potential DOM XSS via URL property access",
	},
}

var dangerousSources = []string{
	"location.hash",
	"location.search",
	"document.URL",
	"document.referrer",
	"window.name",
}

func (a *Analyzer) CheckXSS(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check HTML for XSS patterns
	for _, pattern := range xssPatterns {
		matches := pattern.pattern.FindAllStringIndex(page.HTML, -1)
		for _, match := range matches {
			location := fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, match[0]))
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "XSS",
				Description: pattern.description,
				Severity:    pattern.severity,
				Location:    location,
				Details:     fmt.Sprintf("Pattern: %s", page.HTML[match[0]:match[1]]),
			})
		}
	}

	// Check JavaScript for dangerous sources
	for _, js := range page.JavaScript {
		for _, source := range dangerousSources {
			if strings.Contains(js, source) {
				location := fmt.Sprintf("JavaScript (source: %s)", source)
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "XSS",
					Description: fmt.Sprintf("Potential XSS via dangerous source: %s", source),
					Severity:    "High",
					Location:    location,
					Details:     "Dangerous data source detected in JavaScript",
				})
			}
		}
	}

	return vulnerabilities
}

func findLineNumber(content string, pos int) int {
	lines := strings.Split(content[:pos], "\n")
	return len(lines)
}
