package output

import (
	"encoding/json"
	"fmt"

	"domeye/internal/analyzer"
)

type JSONFormatter struct {
}

func (f *JSONFormatter) Format(results chan analyzer.Result) {
	var allResults []analyzer.Result

	for result := range results {
		allResults = append(allResults, result)
	}

	jsonData, err := json.MarshalIndent(allResults, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		return
	}

	fmt.Println(string(jsonData))
}
