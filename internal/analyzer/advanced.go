package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/Lovepreet-se7en/domeye/internal/scanner"
)

// Additional patterns for more comprehensive DOM vulnerability detection
var domVulnerabilityPatterns = []struct {
	pattern     *regexp.Regexp
	severity    string
	description string
	category    string
}{
	{
		pattern:     regexp.MustCompile(`(?i)(document\.cookie|localStorage|sessionStorage)\s*[+]?=\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "Critical",
		description: "Direct assignment of user-controlled data to storage mechanisms",
		category:    "Storage Injection",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(setTimeout|setInterval)\s*\(\s*(?:"'\s*\+.*(?:location|document\.URL|document\.referrer|window\.name)|(?:location|document\.URL|document\.referrer|window\.name)\s*,)`),
		severity:    "Critical",
		description: "Dynamic code execution with user-controlled input",
		category:    "Code Injection",
	},
	{
		pattern:     regexp.MustCompile(`(?i)Function\s*\(\s*["']\s*\+.*(?:location|document\.URL|document\.referrer|window\.name)`),
		severity:    "Critical",
		description: "Dynamic function creation with user-controlled input",
		category:    "Code Injection",
	},
	{
		pattern:     regexp.MustCompile(`(?i)eval\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "Critical",
		description: "Direct evaluation of user-controlled data",
		category:    "Code Injection",
	},
	{
		pattern:     regexp.MustCompile(`(?i)execScript\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "Critical",
		description: "Execution of user-controlled script",
		category:    "Code Injection",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(\.(href|src|data|formAction|codeBase|lowsrc|background|profile|ping))\s*=\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Assignment of user-controlled data to navigation attributes",
		category:    "Open Redirect",
	},
	{
		pattern:     regexp.MustCompile(`(?i)location\s*[.]\s*(href|assign|replace)\s*=\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Direct assignment to location object with user-controlled data",
		category:    "Open Redirect",
	},
	{
		pattern:     regexp.MustCompile(`(?i)document\.domain\s*=\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Setting document domain with user-controlled data",
		category:    "Domain Manipulation",
	},
	{
		pattern:     regexp.MustCompile(`(?i)(postMessage|dispatchEvent|fireEvent)\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "Medium",
		description: "Sending user-controlled data via messaging systems",
		category:    "Information Disclosure",
	},
	{
		pattern:     regexp.MustCompile(`(?i)WebSocket\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Creating WebSocket connection with user-controlled URL",
		category:    "Connection Hijacking",
	},
	{
		pattern:     regexp.MustCompile(`(?i)XMLHttpRequest\.open\s*\(\s*["']?\s*\w+["']?\s*,\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Making request with user-controlled URL",
		category:    "Request Forgery",
	},
	{
		pattern:     regexp.MustCompile(`(?i)fetch\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Making fetch request with user-controlled URL",
		category:    "Request Forgery",
	},
	{
		pattern:     regexp.MustCompile(`(?i)import\s*\(\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		severity:    "High",
		description: "Importing module with user-controlled path",
		category:    "Module Injection",
	},
}

// CheckAdvancedDOM analyzes for more sophisticated DOM-based vulnerabilities
func (a *Analyzer) CheckAdvancedDOM(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check HTML for advanced patterns
	for _, pattern := range domVulnerabilityPatterns {
		matches := pattern.pattern.FindAllStringIndex(page.HTML, -1)
		for _, match := range matches {
			if isInStringOrComment(page.HTML, match[0]) {
				continue
			}
			location := fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, match[0]))
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        pattern.category,
				Description: pattern.description,
				Severity:    pattern.severity,
				Location:    location,
				Details:     fmt.Sprintf("Pattern: %s", page.HTML[match[0]:match[1]]),
			})
		}
	}

	// Check JavaScript for advanced patterns
	for _, js := range page.JavaScript {
		for _, pattern := range domVulnerabilityPatterns {
			matches := pattern.pattern.FindAllStringIndex(js, -1)
			for _, match := range matches {
				if isInStringOrComment(js, match[0]) {
					continue
				}
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        pattern.category,
					Description: pattern.description,
					Severity:    pattern.severity,
					Location:    "JavaScript",
					Details:     fmt.Sprintf("Pattern: %s", js[match[0]:match[1]]),
				})
			}
		}
	}

	return vulnerabilities
}


// CheckPrototypePollution looks for potential prototype pollution vulnerabilities
func (a *Analyzer) CheckPrototypePollution(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Patterns that could lead to prototype pollution
	pollutionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\.)?(prototype|__proto__|constructor\.prototype)\s*[.\[]\s*["']?\s*(location|document\.URL|document\.referrer|window\.name)`),
		regexp.MustCompile(`(?i)(?:\.)?(prototype|__proto__|constructor\.prototype)\s*[.\[]\s*["']?\s*(location\.hash|location\.search|document\.cookie)`),
	}

	for _, js := range page.JavaScript {
		for _, pattern := range pollutionPatterns {
			matches := pattern.FindAllStringIndex(js, -1)
			for _, match := range matches {
				if isInStringOrComment(js, match[0]) {
					continue
				}
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Prototype Pollution",
					Description: "Potential prototype pollution vulnerability",
					Severity:    "High",
					Location:    "JavaScript",
					Details:     fmt.Sprintf("Pattern: %s", js[match[0]:match[1]]),
				})
			}
		}
	}

	return vulnerabilities
}

var clobberableProps = []string{
	"form", "submit", "elements", "length", "item", "namedItem",
	"action", "method", "target", "enctype", "encoding",
	"name", "value", "type", "defaultChecked", "defaultSelected",
	"checked", "selected", "disabled", "multiple", "required",
	"href", "src", "data", "cookie", "referrer",
}

// CheckDOMClobbering looks for potential DOM clobbering vulnerabilities
func (a *Analyzer) CheckDOMClobbering(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(page.HTML))
	if err != nil {
		return nil
	}

	doc.Find("form, input, object, embed, isindex").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"id", "name"} {
			val, exists := s.Attr(attr)
			if !exists {
				continue
			}
			for _, prop := range clobberableProps {
				if val == prop {
					tagName := goquery.NodeName(s)
					vulnerabilities = append(vulnerabilities, Vulnerability{
						Type:        "DOM Clobbering",
						Description: fmt.Sprintf("DOM clobbering via <%s> element with %s=%q", tagName, attr, val),
						Severity:    "Medium",
						Location:    "HTML",
						Details:     fmt.Sprintf("Element <%s %s=%q> could shadow window.%s in JavaScript", tagName, attr, val, val),
					})
					break
				}
			}
		}
	})

	return vulnerabilities
}