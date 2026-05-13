package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

type JSONFormatter struct {
}

func (f *JSONFormatter) Format(results chan analyzer.Result, w io.Writer) {
	var allResults []analyzer.Result

	for result := range results {
		allResults = append(allResults, result)
	}

	jsonData, err := json.MarshalIndent(allResults, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "Error formatting JSON: %v\n", err)
		return
	}

	fmt.Fprintln(w, string(jsonData))
}
