package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"

	"domeye/internal/analyzer"
	"domeye/internal/output"
	"domeye/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	urlFile      string
	concurrency  int
	timeout     int
	checkXSS    bool
	checkCSP    bool
	checkDOM    bool
	checkSourceSink bool
	checkAll    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan URLs for DOM vulnerabilities",
	Long: `Scan one or more URLs for DOM-based vulnerabilities including XSS, CSP violations, and dangerous DOM manipulations.`,
	Run: func(cmd *cobra.Command, args []string) {
		var urls []string

		// Read URLs from file if provided
		if urlFile != "" {
			file, err := os.Open(urlFile)
			if err != nil {
				log.Fatalf("Error opening URL file: %v", err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				url := scanner.Text()
				if url != "" {
					urls = append(urls, url)
				}
			}
			if err := scanner.Err(); err != nil {
				log.Fatalf("Error reading URL file: %v", err)
			}
		} else if len(args) > 0 {
			// Use URLs from command line arguments
			urls = args
		} else {
			fmt.Println("Please provide URLs as arguments or use --file flag")
			return
		}

		// Set default checks if none specified
		if !checkXSS && !checkCSP && !checkDOM && !checkSourceSink && !checkAll {
			checkAll = true  // Run comprehensive analysis by default
		}

		// Create output formatter
		var formatter output.Formatter
		switch outputFormat {
		case "json":
			formatter = &output.JSONFormatter{}
		case "html":
			formatter = &output.HTMLFormatter{}
		default:
			formatter = &output.TextFormatter{}
		}

		// Process URLs concurrently
		processURLs(urls, formatter)
	},
}

func processURLs(urls []string, formatter output.Formatter) {
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, concurrency)
		results := make(chan analyzer.Result, len(urls))

		// Worker pool
		for _, url := range urls {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				semaphore <- struct{}{} // Acquire
				defer func() { <-semaphore }() // Release

				if verbose {
					fmt.Printf("Scanning: %s\n", u)
				}

				// Fetch the page
				sc := scanner.NewScanner()
				page, err := sc.Scan(u)
				if err != nil {
					log.Printf("Error scanning %s: %v", u, err)
					return
				}

				// Analyze for vulnerabilities
				a := analyzer.NewAnalyzer()
				result := analyzer.Result{
					URL: u,
				}

				// If checkAll is enabled, run comprehensive analysis
				if checkAll {
					allVulns := a.CheckAll(page)
					result.Vulnerabilities = append(result.Vulnerabilities, allVulns...)
				} else {
					// Otherwise run individual checks based on flags
					if checkXSS {
						xssVulns := a.CheckXSS(page)
						result.Vulnerabilities = append(result.Vulnerabilities, xssVulns...)
					}

					if checkCSP {
						cspVulns := a.CheckCSP(page)
						result.Vulnerabilities = append(result.Vulnerabilities, cspVulns...)
					}

					if checkDOM {
						domVulns := a.CheckDOM(page)
						result.Vulnerabilities = append(result.Vulnerabilities, domVulns...)
					}

					if checkSourceSink {
						sourceSinkVulns := a.CheckSourceSink(page)
						result.Vulnerabilities = append(result.Vulnerabilities, sourceSinkVulns...)
					}
				}

				results <- result
			}(url)
		}

		// Close results channel when all workers are done
		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect and format results
		formatter.Format(results)
	}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&urlFile, "file", "f", "", "file containing URLs to scan (one per line)")
	scanCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 5, "number of concurrent scans")
	scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "HTTP timeout in seconds")
	scanCmd.Flags().BoolVar(&checkXSS, "xss", false, "check for XSS vulnerabilities")
	scanCmd.Flags().BoolVar(&checkCSP, "csp", false, "check for CSP violations")
	scanCmd.Flags().BoolVar(&checkDOM, "dom", false, "check for dangerous DOM manipulations")
	scanCmd.Flags().BoolVar(&checkSourceSink, "sourcesink", false, "check for source-sink flow vulnerabilities")
	scanCmd.Flags().BoolVar(&checkAll, "all", false, "run comprehensive analysis (all checks)")
}
