package analyzer

import (
	"fmt"
	"regexp"

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
		pattern:     regexp.MustCompile(`(?i)(setTimeout|setInterval)\s*\(\s*["']\s*\+.*(?:location|document\.URL|document\.referrer|window\.name)`),
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

// CheckDOMClobbering looks for potential DOM clobbering vulnerabilities
func (a *Analyzer) CheckDOMClobbering(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Look for elements with IDs that could clobber important JavaScript variables
	clobberingPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\s*(form|input|object|embed|isindex)\s+[^>]*\bid\s*=\s*["']\s*(form|submit|elements|length|item|namedItem|reset|submit|action|method|target|enctype|encoding|autocomplete|novalidate|autofocus|disabled|form|formaction|formenctype|formmethod|formnovalidate|formtarget|name|value|checked|selected|readonly|required|multiple|min|max|step|pattern|placeholder|size|src|alt|height|width|usemap|ismap|tabindex|accesskey|hidden|contenteditable|spellcheck|translate|dir|lang|xml:lang|title|class|id|style|align|bgcolor|border|hspace|vspace|cite|datetime|pubdate|rel|rev|shape|coords|download|href|hreflang|media|type|sizes|crossorigin|integrity|charset|defer|language|srcdoc|sandbox|seamless|allowfullscreen|allowpaymentrequest|loading|fetchpriority|referrerpolicy|as|impressiondata|impressionexpiry|elementtiming|blocking|blockingurls|blockingtargets|blockingexceptions|blockingrules|blockingfilters|blockingpatterns|blockingstrategies|blockingmechanisms|blockingcontrols|blockingoptions|blockingsettings|blockingpreferences|blockingconfigurations|blockingparameters|blockingarguments|blockingvalues|blockingcriteria|blockingconditions|blockingrulesets|blockingrulegroups|blockingrulecategories|blockingruletypes|blockingruleformats|blockingrulepatterns|blockingruleexpressions|blockingruleconditions|blockingruleactions|blockingruleoutcomes|blockingruleeffects|blockingruleimpacts|blockingruleconsequences|blockingruleresults|blockingruleoutputs|blockingrulebehaviors|blockingruleoperations|blockingrulefunctions|blockingrulemethods|blockingruleprocedures|blockingruleprocesses|blockingruleactivities|blockingruletasks|blockingrulejobs|blockingrulework|blockingruleefforts|blockingruleendeavors|blockingruleundertakings|blockingruleinitiatives|blockingruleprojects|blockingruleprograms|blockingrulecampaigns|blockingrulemovements|blockingruleefforts|blockingruleendeavors|blockingruleinitiatives|blockingruleprojects|blockingruleprograms|blockingrulecampaigns|blockingrulemovements|blockingruleactions|blockingruleactivities|blockingruletasks|blockingrulejobs|blockingrulework|blockingruleefforts|blockingruleendeavors|blockingruleinitiatives|blockingruleprojects|blockingruleprograms|blockingrulecampaigns|blockingrulemovements)\s*["']`),
	}

	for _, pattern := range clobberingPatterns {
		matches := pattern.FindAllStringIndex(page.HTML, -1)
		for _, match := range matches {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "DOM Clobbering",
				Description: "Potential DOM clobbering vulnerability",
				Severity:    "Medium",
				Location:    fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, match[0])),
				Details:     fmt.Sprintf("Element with ID that could clobber JS properties: %s", page.HTML[match[0]:match[1]]),
			})
		}
	}

	return vulnerabilities
}