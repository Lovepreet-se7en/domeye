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
			Type:        "CSP",
			Description: "No Content Security Policy header found",
			Severity:    "High",
			Location:    "HTTP Headers",
			Details:     "CSP header is missing, increasing risk of XSS attacks",
		})
		return vulnerabilities
	}

	// Check for unsafe directives
	cspLower := strings.ToLower(page.CSP)
	for _, directive := range unsafeDirectives {
		if strings.Contains(cspLower, directive) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "CSP",
				Description: fmt.Sprintf("Unsafe CSP directive found: %s", directive),
				Severity:    "High",
				Location:    "CSP Header",
				Details:     fmt.Sprintf("The directive '%s' weakens CSP protection", directive),
			})
		}
	}

	// Check for missing required directives
	for _, directive := range requiredDirectives {
		if !strings.Contains(cspLower, directive) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "CSP",
				Description: fmt.Sprintf("Missing recommended CSP directive: %s", directive),
				Severity:    "Medium",
				Location:    "CSP Header",
				Details:     fmt.Sprintf("The '%s' directive should be explicitly defined", directive),
			})
		}
	}

	// Check for report-uri or report-to
	if !strings.Contains(cspLower, "report-uri") && !strings.Contains(cspLower, "report-to") {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "CSP",
			Description: "CSP violation reporting not configured",
			Severity:    "Low",
			Location:    "CSP Header",
			Details:     "Add report-uri or report-to directive to monitor CSP violations",
		})
	}

	return vulnerabilities
}
