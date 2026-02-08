package analyzer

import (
	"fmt"
	"regexp"

	"github.com/Lovepreet-se7en/domeye/internal/scanner"
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
			snippet := page.HTML[match[0]:match[1]]
			location := fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, match[0]))
			
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "DOM",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Location:       location,
				Details:        fmt.Sprintf("Pattern: %s", snippet),
				ProofOfConcept: generateDOMPOC(pattern.description, snippet),
				Confidence:     "High",
				CVSSScore:      getCVSSScore("DOM", pattern.severity),
				CWEID:          getCWEID("DOM"),
				Remediation:    getDOMRemediation(pattern.description),
				References:     []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting"},
				CodeSnippet:    extractContext(page.HTML, match[0], match[1]),
			})
		}
	}

	// Check JavaScript for event handlers
	for _, js := range page.JavaScript {
		for _, handler := range eventHandlers {
			re := regexp.MustCompile(`(?i)`+handler+`\s*=`)
			if re.MatchString(js) {
				matches := re.FindAllStringIndex(js, -1)
				for _, match := range matches {
					snippet := js[match[0]:match[1]]
					
					vulnerabilities = append(vulnerabilities, Vulnerability{
						Type:           "DOM",
						Description:    fmt.Sprintf("Inline event handler: %s", handler),
						Severity:       "Medium",
						Location:       "JavaScript",
						Details:        "Inline event handlers can lead to security issues",
						ProofOfConcept: generateInlineEventHandlerPOC(handler),
						Confidence:     "Medium",
						CVSSScore:      getCVSSScore("DOM", "Medium"),
						CWEID:          getCWEID("DOM"),
						Remediation:    getDOMRemediation(fmt.Sprintf("Inline event handler: %s", handler)),
						References:     []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting"},
						CodeSnippet:    extractContext(js, match[0], match[1]),
					})
				}
			}
		}
	}

	return vulnerabilities
}

// Helper functions for enhanced DOM analysis

func generateDOMPOC(description, snippet string) string {
	switch {
	case strings.Contains(description, "innerHTML"):
		return fmt.Sprintf(`PoC: <script>document.getElementById('target').innerHTML = '%s';</script>`, snippet)
	case strings.Contains(description, "outerHTML"):
		return fmt.Sprintf(`PoC: <script>element.outerHTML = '%s';</script>`, snippet)
	case strings.Contains(description, "insertAdjacentHTML"):
		return fmt.Sprintf(`PoC: <script>element.insertAdjacentHTML('beforeend', '%s');</script>`, snippet)
	case strings.Contains(description, "document.write"):
		return fmt.Sprintf(`PoC: <script>document.write('%s');</script>`, snippet)
	case strings.Contains(description, "setTimeout"):
		return fmt.Sprintf(`PoC: <script>setTimeout('%s', 1000);</script>`, snippet)
	case strings.Contains(description, "setInterval"):
		return fmt.Sprintf(`PoC: <script>setInterval('%s', 1000);</script>`, snippet)
	case strings.Contains(description, "Function"):
		return fmt.Sprintf(`PoC: <script>var fn = new Function('%s'); fn();</script>`, snippet)
	default:
		return fmt.Sprintf("Potential DOM vulnerability: %s", description)
	}
}

func generateInlineEventHandlerPOC(handler string) string {
	switch handler {
	case "onclick":
		return fmt.Sprintf(`PoC: <button onclick="%s">Click me</button>`, "alert('XSS')")
	case "onload":
		return fmt.Sprintf(`PoC: <body onload="%s">`, "alert('XSS')")
	case "onerror":
		return fmt.Sprintf(`PoC: <img src='invalid.jpg' onerror="%s">`, "alert('XSS')")
	default:
		return fmt.Sprintf("Potential inline event handler vulnerability: %s", handler)
	}
}

func getCVSSScore(vulnType, severity string) string {
	switch severity {
	case "Critical":
		return "9.0-10.0"
	case "High":
		return "7.0-8.9"
	case "Medium":
		return "4.0-6.9"
	case "Low":
		return "0.1-3.9"
	default:
		return "N/A"
	}
}

func getCWEID(vulnType string) string {
	switch vulnType {
	case "XSS":
		return "CWE-79"
	case "CSP":
		return "CWE-693" // Protection Mechanism Failure
	case "DOM":
		return "CWE-116" // Improper Encoding or Escaping of Output
	case "Source-Sink":
		return "CWE-80" // Improper Neutralization of Script-Related HTML Tags in a Web Page
	default:
		return "N/A"
	}
}

func getDOMRemediation(description string) string {
	return "Avoid using dangerous DOM manipulation methods. Sanitize inputs, use safe alternatives like textContent, and implement proper CSP policies."
}

func extractContext(content string, start, end int) string {
	contextSize := 100
	startPos := start - contextSize
	endPos := end + contextSize
	
	if startPos < 0 {
		startPos = 0
	}
	if endPos > len(content) {
		endPos = len(content)
	}
	
	return content[startPos:endPos]
}
