package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// GenerateTargetURLs replaces injection points in the input URL with the payload.
// It mimics the behavior of pvreplace.
func GenerateTargetURLs(inputURL, payload string) ([]string, error) {
	var targets []string

	// Case 1: URL has {payload} placeholder
	if strings.Contains(inputURL, "{payload}") {
		target := strings.ReplaceAll(inputURL, "{payload}", payload)
		targets = append(targets, target)
		return targets, nil
	}

	// Case 2: URL has query parameters
	u, err := url.Parse(inputURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	queryParams := u.Query()
	if len(queryParams) == 0 {
		return nil, fmt.Errorf("no injection points found")
	}

	// Create a target for each parameter being replaced
	for key := range queryParams {
		// Create a copy of the query params
		newParams := url.Values{}
		for k, v := range queryParams {
			if k == key {
				newParams.Set(k, payload)
			} else {
				// Keep other params as is (using the first value if multiple exist, or join them? pvreplace usually replaces value)
				// For simplicity and standard behavior, we keep the original values.
				for _, val := range v {
					newParams.Add(k, val)
				}
			}
		}
		
		// Reconstruct the URL
		newURL := *u
		newURL.RawQuery = newParams.Encode()
		targets = append(targets, newURL.String())
	}

	return targets, nil
}
