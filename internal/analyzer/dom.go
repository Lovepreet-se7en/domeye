package analyzer

import (
	"fmt"
	"regexp"

	"domeye/internal/scanner"
)

var domPatterns = []struct {
	pattern     *regexp.Regexp
	severity    string
	description string
}{
	{
		pattern:     regexp.MustCompile(`(?i)\.innerHTML\s*=`),
		severity:    "High",
		description: "DOM manipulation via innerHTML",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.outerHTML\s*=`),
		severity:    "High",
		description: "DOM manipulation via outerHTML",
	},
	{
		pattern:     regexp.MustCompile(`(?i)\.insertAdjacentHTML\s*\(`),
		severity:    "High",
		description: "DOM manipulation via insertAdjacentHTML",
	},
	{
		pattern:     regexp.MustCompile(`(?i)document\.write\s*\(`),
		severity:    "High",
		description: "Document write operation",
	},
	{
		pattern:     regexp.MustCompile(`(?i)document\.writeln\s*\(`),
		severity:    "High",
		description: "Document writeln operation",
	},
	{
		pattern:     regexp.MustCompile(`(?i)setTimeout\s*\(.*(eval|Function)\s*\(`),
		severity:    "Critical",
		description: "Dynamic code execution via setTimeout",
	},
	{
		pattern:     regexp.MustCompile(`(?i)setInterval\s*\(.*(eval|Function)\s*\(`),
		severity:    "Critical",
		description: "Dynamic code execution via setInterval",
	},
	{
		pattern:     regexp.MustCompile(`(?i)new\s+Function\s*\(`),
		severity:    "Critical",
		description: "Dynamic function creation",
	},
}

var eventHandlers = []string{
	"onload",
	"onclick",
	"onerror",
	"onmouseover",
	"onsubmit",
	"onfocus",
	"onblur",
}

func (a *Analyzer) CheckDOM(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check HTML for DOM manipulation patterns
	for _, pattern := range domPatterns {
		matches := pattern.pattern.FindAllStringIndex(page.HTML, -1)
		for _, match := range matches {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "DOM",
				Description: pattern.description,
				Severity:    pattern.severity,
				Location:    fmt.Sprintf("HTML content"),
				Details:     fmt.Sprintf("Pattern: %s", page.HTML[match[0]:match[1]]),
			})
		}
	}

	// Check JavaScript for event handlers
	for _, js := range page.JavaScript {
		for _, handler := range eventHandlers {
			if regexp.MustCompile(`(?i)`+handler+`\s*=`).MatchString(js) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "DOM",
					Description: fmt.Sprintf("Inline event handler: %s", handler),
					Severity:    "Medium",
					Location:    "JavaScript",
					Details:     "Inline event handlers can lead to security issues",
				})
			}
		}
	}

	return vulnerabilities
}
