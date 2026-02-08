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


