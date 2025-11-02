package main

import (
	"bufio"
	"os"

	"github.com/bytes-Knight/ppfuzz/pkg/browser"
	"github.com/bytes-Knight/ppfuzz/pkg/builder"
	"github.com/bytes-Knight/ppfuzz/pkg/errors"
	"github.com/bytes-Knight/ppfuzz/pkg/fuzzer"
	"github.com/bytes-Knight/ppfuzz/pkg/parser"
)

func main() {
	opts, err := parser.Get()
	errors.Handle(err)

	var urls []string
	if opts.List != "" {
		file, err := os.Open(opts.List)
		errors.Handle(err)
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	}

	var payloads []string
	for _, u := range urls {
		payloads = append(payloads, builder.Query(u)...)
	}

	ctx, cancel := browser.Config(opts.Timeout)
	defer cancel()

	fuzzer.New(payloads, ctx, opts)
}
