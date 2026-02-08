package analyzer

// extractContext extracts a contextual snippet around a given position
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

// getCVSSScore returns the CVSS score range for a given severity
func getCVSSScore(severity string) string {
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

// getCWEID returns the CWE identifier for a given vulnerability type
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