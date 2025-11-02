package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/bytes-Knight/ppfuzz/pkg/parser"
)

// Config sets up a new browser context with a timeout.
func Config(opts *parser.Options) (context.Context, context.CancelFunc) {
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	}
	if opts.IgnoreCertErrors {
		allocOpts = append(allocOpts, chromedp.Flag("ignore-certificate-errors", true))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)

	return ctx, cancel
}
