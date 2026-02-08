package analyzer

import (
	"fmt"
	"strings"

	"github.com/Lovepreet-se7en/domeye/internal/scanner"
)

var unsafeDirectives = []string{
	"unsafe-inline",
	"unsafe-eval",
	"http:",
	"data:",
}

var requiredDirectives = []string{
	"default-src",
	"script-src",
	"style-src",
	"img-src",
}

func (a *Analyzer) CheckCSP(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	if page.CSP == "" {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:           "CSP",
			Description:    "No Content Security Policy header found",
			Severity:       "High",
			Location:       "HTTP Headers",
			Details:        "CSP header is missing, increasing risk of XSS attacks",
			ProofOfConcept: generateCSPBypassPOC("missing"),
			Confidence:     "High",
			CVSSScore:      getCVSSScore("CSP", "High"),
			CWEID:          getCWEID("CSP"),
			Remediation:    "Implement a strong Content Security Policy header to restrict the execution of scripts and other resources.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://content-security-policy.com/"},
			CodeSnippet:    "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
		})
		return vulnerabilities
	}

	// Check for unsafe directives
	cspLower := strings.ToLower(page.CSP)
	for _, directive := range unsafeDirectives {
		if strings.Contains(cspLower, directive) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "CSP",
				Description:    fmt.Sprintf("Unsafe CSP directive found: %s", directive),
				Severity:       "High",
				Location:       "CSP Header",
				Details:        fmt.Sprintf("The directive '%s' weakens CSP protection", directive),
				ProofOfConcept: generateCSPBypassPOC(directive),
				Confidence:     "High",
				CVSSScore:      getCVSSScore("CSP", "High"),
				CWEID:          getCWEID("CSP"),
				Remediation:    fmt.Sprintf("Remove the '%s' directive from your CSP header to strengthen security.", directive),
				References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://content-security-policy.com/"},
				CodeSnippet:    fmt.Sprintf("Current: %s", page.CSP),
			})
		}
	}

	// Check for missing required directives
	for _, directive := range requiredDirectives {
		if !strings.Contains(cspLower, directive) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:           "CSP",
				Description:    fmt.Sprintf("Missing recommended CSP directive: %s", directive),
				Severity:       "Medium",
				Location:       "CSP Header",
				Details:        fmt.Sprintf("The '%s' directive should be explicitly defined", directive),
				ProofOfConcept: generateCSPBypassPOC(fmt.Sprintf("missing-%s", directive)),
				Confidence:     "Medium",
				CVSSScore:      getCVSSScore("CSP", "Medium"),
				CWEID:          getCWEID("CSP"),
				Remediation:    fmt.Sprintf("Add the '%s' directive to your CSP header to improve security.", directive),
				References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://content-security-policy.com/"},
				CodeSnippet:    fmt.Sprintf("Consider adding: %s 'self';", directive),
			})
		}
	}

	// Check for report-uri or report-to
	if !strings.Contains(cspLower, "report-uri") && !strings.Contains(cspLower, "report-to") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:           "CSP",
			Description:    "CSP violation reporting not configured",
			Severity:       "Low",
			Location:       "CSP Header",
			Details:        "Add report-uri or report-to directive to monitor CSP violations",
			ProofOfConcept: generateCSPBypassPOC("no-reporting"),
			Confidence:     "Low",
			CVSSScore:      getCVSSScore("CSP", "Low"),
			CWEID:          getCWEID("CSP"),
			Remediation:    "Add report-uri or report-to directive to your CSP header to monitor violations.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://content-security-policy.com/"},
			CodeSnippet:    "Add: report-uri /csp-report-endpoint/; or report-to csp-report;",
		})
	}

	return vulnerabilities
}

// Helper functions for enhanced CSP analysis

func generateCSPBypassPOC(issueType string) string {
	switch issueType {
	case "missing":
		return `PoC: Without CSP, any script can run: <script>alert('XSS')</script>`
	case "unsafe-inline":
		return `PoC: CSP with 'unsafe-inline' allows inline scripts: <script>alert('XSS')</script>`
	case "unsafe-eval":
		return `PoC: CSP with 'unsafe-eval' allows eval(): <script>eval('alert("XSS")');</script>`
	case "http:":
		return `PoC: CSP allowing HTTP resources can be exploited in MITM attacks`
	case "data:":
		return `PoC: CSP allowing data: URIs can be exploited: <script src="data:text/javascript,alert('XSS')"></script>`
	case "no-reporting":
		fallthrough
	default:
		return fmt.Sprintf("Potential CSP bypass for issue: %s", issueType)
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
