package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	verbose    bool
	format     string
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:   "domeye",
	Short: "DOMEye is a CLI tool for DOM vulnerability analysis",
	Long: `DOMEye is a powerful CLI tool for analyzing web pages for DOM-based vulnerabilities
including XSS, CSP violations, and dangerous DOM manipulations.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			fmt.Println("Verbose mode enabled")
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "output format (text, json, html)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "save output to file")
}
