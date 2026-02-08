package output

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

type HTMLFormatter struct {
}

func (f *HTMLFormatter) Format(results chan analyzer.Result) {
	// Create HTML template
	tmpl := `<!DOCTYPE html>
<html>
<head>
	<title>DOM-Recon Scan Report</title>
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
		h1 { color: #333; }
		.vuln { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
		.severity-critical { background-color: #ffebee; border-left: 5px solid #f44336; }
		.severity-high { background-color: #fff3e0; border-left: 5px solid #ff9800; }
		.severity-medium { background-color: #e8f5e9; border-left: 5px solid #4caf50; }
		.severity-low { background-color: #e3f2fd; border-left: 5px solid #2196f3; }
		.url { font-weight: bold; margin-bottom: 10px; }
		.details { margin-top: 10px; padding: 10px; background-color: #f5f5f5; border-radius: 3px; }
	</style>
</head>
<body>
	<h1>DOM-Recon Scan Report</h1>
	{{range .}}
		<h2 class="url">{{.URL}}</h2>
		{{if .Vulnerabilities}}
			{{range .Vulnerabilities}}
				<div class="vuln severity-{{lower .Severity}}">
					<h3>{{.Type}} - {{.Severity}}</h3>
					<p><strong>Description:</strong> {{.Description}}</p>
					<p><strong>Location:</strong> {{.Location}}</p>
					{{if .Details}}
						<div class="details"><strong>Details:</strong> {{.Details}}</div>
					{{end}}
				</div>
			{{end}}
		{{else}}
			<p>No vulnerabilities found!</p>
		{{end}}
	{{end}}
</body>
</html>`

	// Parse template
	t, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(tmpl)
	if err != nil {
		fmt.Printf("Error parsing template: %v\n", err)
		return
	}

	// Collect results
	var allResults []analyzer.Result
	for result := range results {
		allResults = append(allResults, result)
	}

	// Create output file
	file, err := os.Create("scan_report.html")
	if err != nil {
		fmt.Printf("Error creating HTML file: %v\n", err)
		return
	}
	defer file.Close()

	// Execute template
	err = t.Execute(file, allResults)
	if err != nil {
		fmt.Printf("Error executing template: %v\n", err)
		return
	}

	fmt.Printf("HTML report generated: %s\n", file.Name())
}
