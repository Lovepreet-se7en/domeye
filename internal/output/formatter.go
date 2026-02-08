package output

import (
	"domeye/internal/analyzer"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(results chan analyzer.Result)
}