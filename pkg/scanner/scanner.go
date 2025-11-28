package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bytes-Knight/xssrecon/pkg/utils"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

var specialChars = []string{`'`, `"`, `<`, `>`, `(`, `)`, "`", `{`, `}`, `/`, `\`, `;`}

var conversions = map[string]string{
	"'":  "&#039;",
	`"`:  "&quot;",
	"<":  "&lt;",
	">":  "&gt;",
}

type Options struct {
	UserAgent       string
	Timeout         int
	SkipSpecialChar bool
	NoColor         bool
	Verbose         bool
	JSONOutput      bool
	Proxy           string
	Concurrency     int
	VerifySSL       bool
}

type JSONOutput struct {
	Processing string         `json:"processing"`
	BaseURL    string         `json:"baseurl"`
	Reflected  bool           `json:"reflected"`
	Allowed    []string       `json:"allowed"`
	Blocked    []string       `json:"blocked"`
	Converted  []string       `json:"converted"`
	Count      map[string]int `json:"count"`
}

type Scanner struct {
	opts       Options
	client     *http.Client
	domScanner *DOMScanner
}

func NewScanner(opts Options) (*Scanner, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !opts.VerifySSL},
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	domScanner, err := NewDOMScanner(opts.Timeout, opts.Proxy, opts.VerifySSL)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		opts:       opts,
		client:     client,
		domScanner: domScanner,
	}, nil
}

func (s *Scanner) Close() {
	if s.domScanner != nil {
		s.domScanner.Close()
	}
}

func (s *Scanner) Scan(inputURL string) {
	if !s.opts.JSONOutput {
		if s.opts.NoColor {
			fmt.Printf("\nPROCESSING: %s\n", inputURL)
		} else {
			fmt.Printf("\n\033[96mPROCESSING: %s\033[0m\n", inputURL)
		}
	}

	baseURLs, err := utils.GenerateTargetURLs(inputURL, "rix4uni")
	if err != nil {
		if s.opts.Verbose {
			fmt.Printf("Error generating target URLs: %v\n", err)
		}
		return
	}

	for _, baseURL := range baseURLs {
		s.processBaseURL(inputURL, baseURL)
	}
}

func (s *Scanner) processBaseURL(inputURL, baseURL string) {
	var output JSONOutput
	output.Processing = inputURL
	output.BaseURL = baseURL

	if !s.opts.JSONOutput {
		if s.opts.NoColor {
			fmt.Printf("BASEURL: %s\n", baseURL)
		} else {
			fmt.Printf("\033[94mBASEURL: %s\033[0m\n", baseURL)
		}
	}

	var body string
	var err error
	var reflectedInDOM bool

	// 1. Check Normal Reflection
	body, err = s.fetch(baseURL)
	if err != nil {
		if s.opts.Verbose {
			fmt.Printf("Error fetching base URL: %v\n", err)
		}
		return
	}

	if !strings.Contains(body, "rix4uni") {
		// 2. Check DOM Reflection
		body, err = s.domScanner.GetDOM(baseURL)
		if err != nil {
			if s.opts.Verbose {
				fmt.Printf("Error fetching DOM: %v\n", err)
			}
			return
		}
		if strings.Contains(body, "rix4uni") {
			reflectedInDOM = true
		}
	}

	if strings.Contains(body, "rix4uni") {
		output.Reflected = true
		s.printReflected(true)

		if s.opts.SkipSpecialChar {
			s.printJSON(output)
			return
		}

		s.checkSpecialChars(inputURL, baseURL, reflectedInDOM, &output)
		s.printJSON(output)

	} else {
		output.Reflected = false
		s.printReflected(false)
		s.printJSON(output)
	}
}

func (s *Scanner) checkSpecialChars(inputURL, baseURL string, reflectedInDOM bool, output *JSONOutput) {
	allowed := []string{}
	blocked := []string{}
	converted := []string{}

	for _, char := range specialChars {
		testURLs, err := utils.GenerateTargetURLs(inputURL, "rix4uni"+char)
		if err != nil {
			continue
		}

		// We only check the first generated URL for the char to avoid explosion
		if len(testURLs) == 0 {
			continue
		}
		testURL := testURLs[0]

		if s.opts.Verbose && !s.opts.JSONOutput {
			if s.opts.NoColor {
				fmt.Printf("CHECKING: %s\n", testURL)
			} else {
				fmt.Printf("\033[95mCHECKING: %s\033[0m\n", testURL)
			}
		}

		var testBody string
		if reflectedInDOM {
			testBody, err = s.domScanner.GetDOM(testURL)
		} else {
			testBody, err = s.fetch(testURL)
		}

		if err != nil {
			continue
		}

		if strings.Contains(testBody, "rix4uni"+char) {
			allowed = append(allowed, char)
		} else if conv, exists := conversions[char]; exists && strings.Contains(testBody, "rix4uni"+conv) {
			converted = append(converted, fmt.Sprintf("%s ➔ %s", char, conv))
		} else {
			blocked = append(blocked, char)
		}
	}

	output.Allowed = allowed
	output.Blocked = blocked
	output.Converted = converted
	output.Count = map[string]int{
		"allowed":   len(allowed),
		"blocked":   len(blocked),
		"converted": len(converted),
	}

	if !s.opts.JSONOutput {
		if s.opts.NoColor {
			fmt.Printf("ALLOWED: %v\n", allowed)
			fmt.Printf("BLOCKED: %v\n", blocked)
			fmt.Printf("CONVERTED: %v\n", converted)
		} else {
			fmt.Printf("\033[32mALLOWED: %v\033[0m\n", allowed)
			fmt.Printf("\033[31mBLOCKED: %v\033[0m\n", blocked)
			fmt.Printf("\033[33mCONVERTED: %v\033[0m\n", converted)
		}
	}
}

func (s *Scanner) fetch(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", s.opts.UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func (s *Scanner) printReflected(reflected bool) {
	if s.opts.JSONOutput {
		return
	}
	if reflected {
		if s.opts.NoColor {
			fmt.Println("REFLECTED: YES")
		} else {
			fmt.Println("\033[92mREFLECTED: YES\033[0m")
		}
	} else {
		if s.opts.NoColor {
			fmt.Println("REFLECTED: NO")
		} else {
			fmt.Println("\033[91mREFLECTED: NO\033[0m")
		}
	}
}

func (s *Scanner) printJSON(output JSONOutput) {
	if !s.opts.JSONOutput {
		return
	}
	// Initialize empty slices if nil to ensure JSON output is consistent [] instead of null
	if output.Allowed == nil { output.Allowed = []string{} }
	if output.Blocked == nil { output.Blocked = []string{} }
	if output.Converted == nil { output.Converted = []string{} }
	if output.Count == nil { output.Count = map[string]int{"allowed": 0, "blocked": 0, "converted": 0} }

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

// DOMScanner handles headless browser interactions
type DOMScanner struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	ctx         context.Context
	ctxCancel   context.CancelFunc
}

func NewDOMScanner(timeout int, proxy string, verifySSL bool) (*DOMScanner, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	if !verifySSL {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}

	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)

	return &DOMScanner{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		ctx:         ctx,
		ctxCancel:   ctxCancel,
	}, nil
}

func (s *DOMScanner) Close() {
	s.ctxCancel()
	s.allocCancel()
}

func (s *DOMScanner) GetDOM(url string) (string, error) {
	var dom string
	// Create a timeout context for the navigation
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Simple wait for network idle or just a small delay
			// Using a fixed delay for simplicity as network idle can be flaky
			time.Sleep(2 * time.Second)
			return nil
		}),
		chromedp.OuterHTML("html", &dom),
	)
	if err != nil {
		return "", err
	}
	return dom, nil
}
