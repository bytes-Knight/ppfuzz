package main

import (
	"bufio"
	"os"

	"ppfuzz/pkg/browser"
	"ppfuzz/pkg/builder"
	"ppfuzz/pkg/errors"
	"ppfuzz/pkg/fuzzer"
	"ppfuzz/pkg/parser"
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
