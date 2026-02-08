package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Lovepreet-se7en/domeye/internal/scanner"
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
			snippet := page.HTML[match[0]:match[1]]
			location := fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, match[0]))
			
			// Determine confidence level based on pattern
			confidence := "High"
			if strings.Contains(snippet, "innerHTML") || strings.Contains(snippet, "eval") {
				confidence = "High"
			} else {
				confidence = "Medium"
			}
			
			// Generate POC based on the vulnerability type
			poc := generateXSSEXPoc(snippet, sourceSinkAnalysis(page, snippet))
			
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "XSS",
				Description:    pattern.description,
				Severity:       pattern.severity,
				Location:       location,
				Details:        fmt.Sprintf("Pattern: %s", snippet),
				ProofOfConcept: poc,
				Confidence:     confidence,
				CVSSScore:      getXSSCVSSScore("XSS", pattern.severity),
				CWEID:          getXSSCWEID("XSS"),
				Remediation:    getXSSRemediation(pattern.description),
				References:     []string{"https://owasp.org/www-community/attacks/DOM_Based_XSS"},
				CodeSnippet:    extractContext(page.HTML, match[0], match[1]),
			})
		}
	}

	// Check JavaScript for dangerous sources
	for _, js := range page.JavaScript {
		for _, source := range dangerousSources {
			if strings.Contains(js, source) {
				location := fmt.Sprintf("JavaScript (source: %s)", source)
				
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:           "XSS",
					Description:    fmt.Sprintf("Potential XSS via dangerous source: %s", source),
					Severity:       "High",
					Location:       location,
					Details:        "Dangerous data source detected in JavaScript",
					ProofOfConcept: generateSourceBasedPOC(source),
					Confidence:     "Medium",
					CVSSScore:      getXSSCVSSScore("XSS", "High"),
					CWEID:          getXSSCWEID("XSS"),
					Remediation:    getXSSRemediation(fmt.Sprintf("XSS via %s", source)),
					References:     []string{"https://owasp.org/www-community/attacks/DOM_Based_XSS"},
					CodeSnippet:    extractContext(js, strings.Index(js, source), strings.Index(js, source)+len(source)),
				})
			}
		}
	}

	return vulnerabilities
}

// Helper functions for enhanced analysis

func generateXSSEXPoc(pattern string, hasSourceSink bool) string {
	switch {
	case strings.Contains(strings.ToLower(pattern), "innerhtml"):
		if hasSourceSink {
			return fmt.Sprintf(`<script>document.body.innerHTML = location.hash.substring(1);</script> <!-- PoC: ?#<img src=x onerror=alert('XSS')> -->`)
		}
		return fmt.Sprintf(`PoC: document.body.innerHTML = "%s";`, pattern)
	case strings.Contains(strings.ToLower(pattern), "eval"):
		if hasSourceSink {
			return `<script>eval(location.hash.substring(1));</script> <!-- PoC: ?#alert('XSS') -->`
		}
		return fmt.Sprintf(`PoC: eval("%s");`, pattern)
	case strings.Contains(strings.ToLower(pattern), "document.write"):
		if hasSourceSink {
			return `<script>document.write(location.hash.substring(1));</script> <!-- PoC: ?#<img src=x onerror=alert('XSS')> -->`
		}
		return fmt.Sprintf(`PoC: document.write("%s");`, pattern)
	default:
		return fmt.Sprintf("Potential XSS with pattern: %s", pattern)
	}
}

func generateSourceBasedPOC(source string) string {
	switch source {
	case "location.hash":
		return `PoC: <script>alert(document.location.hash.substring(1));</script> <!-- Append #test to URL -->`
	case "location.search":
		return `PoC: <script>alert(document.location.search);</script> <!-- Append ?param=test to URL -->`
	case "document.URL":
		return `PoC: <script>alert(document.URL);</script>`
	case "document.referrer":
		return `PoC: <script>alert(document.referrer);</script>`
	case "window.name":
		return `PoC: <script>alert(window.name);</script> <!-- Set window.name in opener -->`
	default:
		return fmt.Sprintf("Potential XSS via source: %s", source)
	}
}

func getXSSCVSSScore(vulnType, severity string) string {
	return getCVSSScore(severity)
}

func getXSSCWEID(vulnType string) string {
	return getCWEID(vulnType)
}

func getXSSRemediation(description string) string {
	return "Sanitize user inputs before using them in DOM operations. Use safe methods like textContent instead of innerHTML. Implement proper Content Security Policy (CSP)."
}


func sourceSinkAnalysis(page *scanner.Page, pattern string) bool {
	// Simple check to see if both sources and sinks exist in the page
	hasSource := false
	for _, source := range dangerousSources {
		if strings.Contains(page.HTML, source) || containsAnyJS(page.JavaScript, source) {
			hasSource = true
			break
		}
	}
	
	hasSink := strings.Contains(page.HTML, pattern)
	
	return hasSource && hasSink
}

func containsAnyJS(jsList []string, substr string) bool {
	for _, js := range jsList {
		if strings.Contains(js, substr) {
			return true
		}
	}
	return false
}

func findLineNumber(content string, pos int) int {
	lines := strings.Split(content[:pos], "\n")
	return len(lines)
}
