package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	devtoolsURL := "ws://127.0.0.1:9222"

	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(context.Background(), devtoolsURL)
	defer cancelAlloc()

	ctx, cancelCtx := chromedp.NewContext(allocCtx)
	defer cancelCtx()

	// 120-second threshold matching your environment parameters
	ctx, cancelTimeout := context.WithTimeout(ctx, 120*time.Second)
	defer cancelTimeout()

	var resultHTML string
	err := chromedp.Run(ctx,
		chromedp.Navigate("http://localhost:8081/app"),

		chromedp.WaitVisible(`#sidebarSearch`, chromedp.ByID),
		chromedp.Click(`#sidebarSearch`, chromedp.ByID),

		chromedp.WaitVisible(`#userSearch`, chromedp.ByID),

		// Set the text via JS and trigger input handlers
		chromedp.Evaluate(`
			(function() {
				const textarea = document.getElementById('userSearch');
				textarea.value = "192.168.1.100\nmalicious-domain.io";
				
				// Dispatch standard input change notifications
				textarea.dispatchEvent(new Event('input', { bubbles: true }));
				textarea.dispatchEvent(new Event('change', { bubbles: true }));
			})()
		`, nil),

		// Now use chromedp's native click handler directly on the search button
		// instead of relying entirely on the JS context evaluation.
		chromedp.WaitVisible(`#searchButton`, chromedp.ByID),
		chromedp.Click(`#searchButton`, chromedp.ByID),

		// Fallback: If native click fails due to z-indexing or Bulma CSS rendering quirks,
		// we force an explicit DOM-level click action immediately afterward.
		chromedp.Evaluate(`
			(function() {
				const btn = document.getElementById('searchButton');
				if (btn) {
					btn.focus();
					btn.click();
				}
			})()
		`, nil),

		// Wait for the UI state change
		chromedp.WaitVisible(`#iocSelectionArea, #matchBox`, chromedp.ByID),
		chromedp.Sleep(5*time.Second),

		chromedp.InnerHTML(`#matchBox`, &resultHTML, chromedp.ByID),
	)

	if err != nil {
		log.Fatalf("Automation stalled or failed: %v", err)
	}

	// Structuralize local document return matrix
	fullHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@1.0.2/css/bulma.min.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <title>ThreatPunch Export Matrix</title>
    <style>
        body { background-color: #000000; color: #ffffff; padding: 2rem; }
        .box { border: 1px solid #333333; }
    </style>
</head>
<body>
    <div class="container">
        <div class="box has-background-dark">
            %s
        </div>
    </div>
</body>
</html>`, resultHTML)

	outputPath := "search_result.html"
	err = os.WriteFile(outputPath, []byte(fullHTML), 0644)
	if err != nil {
		log.Fatalf("Failed to write HTML file to target storage path: %v", err)
	}

	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		log.Fatalf("Failed to resolve local absolute storage path target: %v", err)
	}

	fmt.Printf("Execution successfully completed. Export matrix parsed to location:\nfile://%s\n", absPath)
}

/*
chromedp.Evaluate(fmt.Sprintf(`
			(async function() {
				// 1. Automatically extract the CSRF token if the app stores it in a meta tag or header
				// (Adjust this selector based on how ThreatPunch tracks CSRF tokens)
				const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || "";

				// 2. Dispatch a native fetch request. Chrome automatically appends
				// all Session Cookies, HttpOnly tokens, and credentials.
				const response = await fetch('/api/v1/bulk-search', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-CSRF-Token': csrfToken // Pass the extracted token if required
					},
					body: JSON.stringify(%s)
				});

				return await response.text();
			})()
		`, bulkPayloadJSON), &apiResponse),
	)
*/
