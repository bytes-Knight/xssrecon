package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"github.com/bytes-Knight/xssrecon/banner"
	"github.com/bytes-Knight/xssrecon/pkg/scanner"
	"github.com/spf13/pflag"
)

func main() {
	userAgent := pflag.StringP("user-agent", "H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests.")
	timeout := pflag.IntP("timeout", "t", 15, "Timeout for HTTP requests in seconds.")
	skipSpecialChar := pflag.BoolP("skipspecialchar", "s", false, "Only check rix4uni in reponse and move to next url, skip checking special characters.")
	noColor := pflag.Bool("no-color", false, "Do not use colored output.")
	silent := pflag.Bool("silent", false, "silent mode.")
	version := pflag.Bool("version", false, "Print the version of the tool and exit.")
	verbose := pflag.Bool("verbose", false, "Enable verbose output for debugging purposes.")
	jsonOutput := pflag.Bool("json", false, "Output results in JSON format.")
	proxy := pflag.StringP("proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080)")
	concurrency := pflag.IntP("concurrency", "c", 10, "Number of concurrent workers.")
	verifySSL := pflag.Bool("verify-ssl", false, "Verify SSL certificates.")
	pflag.Parse()

	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	if !*silent {
		banner.PrintBanner()
	}

	opts := scanner.Options{
		UserAgent:       *userAgent,
		Timeout:         *timeout,
		SkipSpecialChar: *skipSpecialChar,
		NoColor:         *noColor,
		Verbose:         *verbose,
		JSONOutput:      *jsonOutput,
		Proxy:           *proxy,
		Concurrency:     *concurrency,
		VerifySSL:       *verifySSL,
	}

	s, err := scanner.NewScanner(opts)
	if err != nil {
		fmt.Printf("Error initializing scanner: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	// Worker Pool
	jobs := make(chan string)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				s.Scan(url)
			}
		}()
	}

	// Read input
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		jobs <- sc.Text()
	}

	close(jobs)
	wg.Wait()

	if err := sc.Err(); err != nil {
		fmt.Printf("Error reading input: %v\n", err)
	}
}
