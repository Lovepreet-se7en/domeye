package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type Page struct {
	URL        string
	HTML       string
	JavaScript []string
	Headers    http.Header
	CSP        string
}

type Scanner struct {
	client *http.Client
}

func NewScanner() *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression: false,
			},
		},
	}
}

func (s *Scanner) Scan(url string) (*Page, error) {
	// Ensure URL has proper scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	resp, err := s.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// Extract JavaScript
	var javascript []string
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			javascript = append(javascript, fmt.Sprintf("External: %s", src))
		} else {
			javascript = append(javascript, s.Text())
		}
	})

	// Extract CSP header
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		csp = resp.Header.Get("Content-Security-Policy-Report-Only")
	}

	return &Page{
		URL:        url,
		HTML:       string(body),
		JavaScript: javascript,
		Headers:    resp.Header,
		CSP:        csp,
	}, nil
}
