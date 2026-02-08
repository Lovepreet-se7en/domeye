package output

import (
	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

// Formatter defines the interface for output formatters
type Formatter interface {
	Format(results chan analyzer.Result)
}