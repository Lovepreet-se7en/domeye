package analyzer

import (
	"fmt"
	"regexp"

	"github.com/Lovepreet-se7en/domeye/internal/scanner"
)

// SourceSink represents a potential source-sink vulnerability pair
type SourceSink struct {
	Source      string
	Sink        string
	CodeSnippet string
	Line        int
}

// Common sources that can lead to DOM vulnerabilities
var domSources = []string{
	"document.URL",
	"document.documentURI", 
	"document.URLUnencoded",
	"document.baseURI",
	"location",
	"location.href",
	"location.hash",
	"location.search",
	"document.cookie",
	"document.referrer",
	"window.name",
	"history.pushState",
	"history.replaceState",
	"localStorage",
	"sessionStorage",
	"IndexedDB",
	"Database",
}

// Common sinks that can lead to DOM vulnerabilities
var domSinks = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.innerHTML\s*=`),
	regexp.MustCompile(`(?i)\.outerHTML\s*=`),
	regexp.MustCompile(`(?i)\.insertAdjacentHTML\s*\(`),
	regexp.MustCompile(`(?i)\.onevent\s*=`),
	regexp.MustCompile(`(?i)document\.write\s*\(`),
	regexp.MustCompile(`(?i)document\.writeln\s*\(`),
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)setTimeout\s*\([^,]*[`+"`"+`"'].*[`+"`"+`"']`),
	regexp.MustCompile(`(?i)setInterval\s*\([^,]*[`+"`"+`"'].*[`+"`"+`"']`),
	regexp.MustCompile(`(?i)Function\s*\([^,]*[`+"`"+`"'].*[`+"`"+`"']`),
	regexp.MustCompile(`(?i)execScript\s*\(`),
	regexp.MustCompile(`(?i)msSetImmediate\s*\(`),
	regexp.MustCompile(`(?i)crypto.generateCRMFRequest\s*\(`),
	regexp.MustCompile(`(?i)navigate\s*\(`),
	regexp.MustCompile(`(?i)documentFragment\.querySelector\s*\(`),
	regexp.MustCompile(`(?i)\.setAttribute\s*\(\s*['"`+"`"+`][^'"`+"`"+`]*['"`+"`"+`]\s*,\s*[^)]+`),
}

// jQuery sinks that can lead to DOM vulnerabilities
var jquerySinks = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.add\s*\(`),
	regexp.MustCompile(`(?i)\.after\s*\(`),
	regexp.MustCompile(`(?i)\.append\s*\(`),
	regexp.MustCompile(`(?i)\.animate\s*\(`),
	regexp.MustCompile(`(?i)\.insertAfter\s*\(`),
	regexp.MustCompile(`(?i)\.insertBefore\s*\(`),
	regexp.MustCompile(`(?i)\.before\s*\(`),
	regexp.MustCompile(`(?i)\.html\s*\(`),
	regexp.MustCompile(`(?i)\.prepend\s*\(`),
	regexp.MustCompile(`(?i)\.replaceAll\s*\(`),
	regexp.MustCompile(`(?i)\.replaceWith\s*\(`),
	regexp.MustCompile(`(?i)\.wrap\s*\(`),
	regexp.MustCompile(`(?i)\.wrapInner\s*\(`),
	regexp.MustCompile(`(?i)\.wrapAll\s*\(`),
	regexp.MustCompile(`(?i)\.has\s*\(`),
	regexp.MustCompile(`(?i)\.constructor\s*\(`),
	regexp.MustCompile(`(?i)\.init\s*\(`),
	regexp.MustCompile(`(?i)\.index\s*\(`),
	regexp.MustCompile(`(?i)jQuery\.parseHTML\s*\(`),
	regexp.MustCompile(`(?i)\$\.parseHTML\s*\(`),
}

func (a *Analyzer) CheckSourceSink(page *scanner.Page) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check HTML content for source-sink pairs
	htmlSources := findSources(page.HTML)
	htmlSinks := findSinks(page.HTML)

	for _, source := range htmlSources {
		for _, sink := range htmlSinks {
			// Check if source and sink are in the same script or related context
			if isRelated(source, sink, page.HTML) {
				path := buildSourceSinkPath(page.HTML, source.Pattern, sink.Pattern)
				poc := generateSourceSinkPOC(source.Pattern, sink.Pattern)
				
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:           "Source-Sink Flow",
					Description:    fmt.Sprintf("Potential source-sink vulnerability: %s -> %s", source.Pattern, sink.Pattern),
					Severity:       "High",
					Location:       fmt.Sprintf("HTML line %d", findLineNumber(page.HTML, source.Position)),
					Details:        fmt.Sprintf("Source: %s, Sink: %s", source.Pattern, sink.Pattern),
					ProofOfConcept: poc,
					Confidence:     "High",
					CVSSScore:      getCVSSScore("Source-Sink", "High"),
					CWEID:          getCWEID("Source-Sink"),
					Remediation:    "Validate and sanitize data from sources before passing to sinks. Use proper encoding and escaping.",
					References:     []string{"https://owasp.org/www-community/attacks/DOM_Based_XSS", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"},
					SourceSinkPath: path,
					CodeSnippet:    extractContext(page.HTML, source.Position, sink.Position),
				})
			}
		}
	}

	// Check JavaScript content for source-sink pairs
	for _, js := range page.JavaScript {
		jsSources := findSources(js)
		jsSinks := findSinks(js)

		for _, source := range jsSources {
			for _, sink := range jsSinks {
				// Check if source and sink are in the same script or related context
				if isRelated(source, sink, js) {
					path := buildSourceSinkPath(js, source.Pattern, sink.Pattern)
					poc := generateSourceSinkPOC(source.Pattern, sink.Pattern)
					
					vulnerabilities = append(vulnerabilities, Vulnerability{
						Type:           "Source-Sink Flow",
						Description:    fmt.Sprintf("Potential source-sink vulnerability: %s -> %s", source.Pattern, sink.Pattern),
						Severity:       "High",
						Location:       "JavaScript",
						Details:        fmt.Sprintf("Source: %s, Sink: %s, Code: %s", source.Pattern, sink.Pattern, truncateString(sink.CodeSnippet, 100)),
						ProofOfConcept: poc,
						Confidence:     "High",
						CVSSScore:      getCVSSScore("Source-Sink", "High"),
						CWEID:          getCWEID("Source-Sink"),
						Remediation:    "Validate and sanitize data from sources before passing to sinks. Use proper encoding and escaping.",
						References:     []string{"https://owasp.org/www-community/attacks/DOM_Based_XSS", "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"},
						SourceSinkPath: path,
						CodeSnippet:    extractContext(js, source.Position, sink.Position),
					})
				}
			}
		}
	}

	return vulnerabilities
}

// SourceInfo holds information about a found source
type SourceInfo struct {
	Pattern  string
	Position int
}

// SinkInfo holds information about a found sink
type SinkInfo struct {
	Pattern   string
	Position  int
	CodeSnippet string
}

func findSources(content string) []SourceInfo {
	var sources []SourceInfo
	
	for _, source := range domSources {
		// Create a regex for the source pattern
		re := regexp.MustCompile(regexp.QuoteMeta(source))
		matches := re.FindAllStringIndex(content, -1)
		
		for _, match := range matches {
			sources = append(sources, SourceInfo{
				Pattern:  source,
				Position: match[0],
			})
		}
	}
	
	return sources
}

func findSinks(content string) []SinkInfo {
	var sinks []SinkInfo
	
	// Check for regular DOM sinks
	for _, sink := range domSinks {
		matches := sink.FindAllStringIndex(content, -1)
		for _, match := range matches {
			// Extract the code snippet around the sink
			start := max(0, match[0]-50)
			end := min(len(content), match[1]+50)
			snippet := content[start:end]
			
			sinks = append(sinks, SinkInfo{
				Pattern:    sink.String(),
				Position:   match[0],
				CodeSnippet: snippet,
			})
		}
	}
	
	// Check for jQuery sinks
	for _, sink := range jquerySinks {
		matches := sink.FindAllStringIndex(content, -1)
		for _, match := range matches {
			// Extract the code snippet around the sink
			start := max(0, match[0]-50)
			end := min(len(content), match[1]+50)
			snippet := content[start:end]
			
			sinks = append(sinks, SinkInfo{
				Pattern:    sink.String(),
				Position:   match[0],
				CodeSnippet: snippet,
			})
		}
	}
	
	return sinks
}

// isRelated checks if a source and sink are likely related in the code
func isRelated(source SourceInfo, sink SinkInfo, content string) bool {
	// Simple heuristic: if the source appears before the sink in the content
	// and they're within a reasonable distance, they might be related
	if source.Position < sink.Position {
		distance := sink.Position - source.Position
		// If the distance is less than 1000 characters, consider them potentially related
		return distance < 1000
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Enhanced helper functions for detailed analysis

func buildSourceSinkPath(content, source, sink string) string {
	// Find positions of source and sink in content
	sourcePos := strings.Index(content, source)
	sinkPos := strings.Index(content, sink)
	
	if sourcePos == -1 || sinkPos == -1 {
		return "Could not determine path"
	}
	
	// Extract the code between source and sink
	start := sourcePos
	end := sinkPos + len(sink)
	
	if start > end {
		// Swap if source comes after sink
		start, end = end, start
	}
	
	// Limit the path length to prevent huge outputs
	if end-start > 500 {
		end = start + 500
	}
	
	path := content[start:end]
	
	// Clean up the path to make it readable
	path = strings.ReplaceAll(path, "\n", "\\n")
	path = strings.ReplaceAll(path, "\t", "\\t")
	
	return path
}

func generateSourceSinkPOC(source, sink string) string {
	// Generate a POC based on the source and sink types
	pocTemplate := ""
	
	switch {
	case (source == "location.hash" || source == "location.search") && 
	     (strings.Contains(sink, "innerHTML") || strings.Contains(sink, "outerHTML")):
		pocTemplate = fmt.Sprintf(
			`PoC: %s -> %s
Example: <script>%s = %s;</script>
Test URL: ?#<img src=x onerror=alert('XSS')>`,
			source, sink, sink, source)
	case strings.Contains(sink, "eval") && 
	     (strings.Contains(source, "location") || strings.Contains(source, "document")):
		pocTemplate = fmt.Sprintf(
			`PoC: %s -> %s
Example: <script>eval(%s);</script>
Test URL: ?eval=alert('XSS')`,
			source, sink, source)
	default:
		pocTemplate = fmt.Sprintf("Potential source-sink flow: %s -> %s", source, sink)
	}
	
	return pocTemplate
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

func truncateString(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen] + "..."
}