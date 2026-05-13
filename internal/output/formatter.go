package output

import (
	"io"

	"github.com/Lovepreet-se7en/domeye/internal/analyzer"
)

type Formatter interface {
	Format(results chan analyzer.Result, w io.Writer)
}