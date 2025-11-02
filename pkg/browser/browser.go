package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// Config sets up a new browser context with a timeout.
func Config(timeout int) (context.Context, context.CancelFunc) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(string, ...interface{}) {}))
	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)

	return ctx, cancel
}
