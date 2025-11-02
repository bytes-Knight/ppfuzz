package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// Config sets up a new browser context with a timeout.
func Config(timeout int) (context.Context, context.CancelFunc) {
	ctx, cancel := chromedp.NewContext(context.Background())
	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)

	return ctx, cancel
}
