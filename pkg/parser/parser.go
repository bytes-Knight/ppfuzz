package parser

import "github.com/spf13/pflag"

// Options holds the command-line options
type Options struct {
	List        string
	Timeout     int
	Concurrency int
}

// Get fetches and parses the command-line options
func Get() (*Options, error) {
	opts := &Options{}

	pflag.StringVarP(&opts.List, "list", "l", "", "List of target URLs")
	pflag.IntVarP(&opts.Timeout, "timeout", "t", 60, "Max. time allowed for connection (s)")
	pflag.IntVarP(&opts.Concurrency, "concurrency", "c", 15, "Set the concurrency level")

	pflag.Parse()

	return opts, nil
}
