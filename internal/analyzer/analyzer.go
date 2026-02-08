package analyzer

import (
	"github.com/Lovepreet-se7en/domeye/internal/scanner"
)

type Vulnerability struct {
    Type        string
    Description string
    Severity    string
    Location    string
    Details     string
    ProofOfConcept string  // Detailed POC for exploitation
    Confidence  string    // Confidence level (High, Medium, Low)
    CVSSScore   string    // CVSS score if available
    CWEID       string    // CWE identifier
    Remediation string    // Suggested remediation
    References  []string  // Related references and resources
    SourceSinkPath string // Path from source to sink for data flow analysis
    CodeSnippet string   // Relevant code snippet showing the vulnerability
}

type Result struct {
    URL             string
    Vulnerabilities []Vulnerability
}

type Analyzer struct {
    // Add any configuration fields here
}

func NewAnalyzer() *Analyzer {
    return &Analyzer{}
}

// CheckAll performs all available analyses
func (a *Analyzer) CheckAll(page *scanner.Page) []Vulnerability {
    var allVulnerabilities []Vulnerability
    
    // Perform all individual analyses
    allVulnerabilities = append(allVulnerabilities, a.CheckXSS(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckCSP(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckDOM(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckSourceSink(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckAdvancedDOM(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckPrototypePollution(page)...)
    allVulnerabilities = append(allVulnerabilities, a.CheckDOMClobbering(page)...)
    
    return allVulnerabilities
}


