package scanner

import (
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"net/http"
)

type Page struct {
	URL        string
	HTML       string
	JavaScript []string
	Headers    http.Header
	CSP        string
}

type Scanner struct {
	client  *http.Client
	maxBody int64
}

func NewScanner() *Scanner {
	return &Scanner{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
			},
		},
		maxBody: 400 * 1024,
	}
}

func (s *Scanner) resolveURL(src, pageURL string) string {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	if strings.HasPrefix(src, "//") {
		parsed, err := url.Parse(pageURL)
		if err != nil {
			return "https:" + src
		}
		return parsed.Scheme + ":" + src
	}
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return src
	}
	parsed.Path = path.Join(path.Dir(parsed.Path), src)
	return parsed.String()
}

func (s *Scanner) fetchScript(src string) string {
	resp, err := s.client.Get(src)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBody))
	if err != nil {
		return ""
	}
	return string(body)
}

func (s *Scanner) Scan(pageURL string) (*Page, error) {
	if !strings.HasPrefix(pageURL, "http://") && !strings.HasPrefix(pageURL, "https://") {
		pageURL = "https://" + pageURL
	}

	resp, err := s.client.Get(pageURL)
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

	var javascript []string

	// 2a: Extract inline and external scripts
	doc.Find("script").Each(func(i int, sel *goquery.Selection) {
		if src, exists := sel.Attr("src"); exists {
			externalURL := s.resolveURL(src, pageURL)
			content := s.fetchScript(externalURL)
			if content != "" {
				javascript = append(javascript, fmt.Sprintf("// from %s\n%s", externalURL, content))
			}
		} else {
			text := sel.Text()
			if strings.TrimSpace(text) != "" {
				javascript = append(javascript, text)
			}
		}
	})

	// 2b: Extract inline event handlers (onclick, onerror, etc.)
	eventHandlerAttrs := []string{
		"onload", "onunload", "onscroll",
		"onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmousemove", "onmouseout",
		"onfocus", "onblur", "onchange", "onsubmit", "onreset", "onselect",
		"onkeydown", "onkeypress", "onkeyup",
		"onerror", "onabort",
	}

	doc.Find("*").Each(func(i int, sel *goquery.Selection) {
		for _, attr := range eventHandlerAttrs {
			if val, exists := sel.Attr(attr); exists && strings.TrimSpace(val) != "" {
				javascript = append(javascript, fmt.Sprintf("// inline %s handler\n%s", attr, val))
			}
		}
	})

	// Extract CSP header
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		csp = resp.Header.Get("Content-Security-Policy-Report-Only")
	}

	return &Page{
		URL:        pageURL,
		HTML:       string(body),
		JavaScript: javascript,
		Headers:    resp.Header,
		CSP:        csp,
	}, nil
}
