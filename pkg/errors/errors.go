package errors

import (
	"errors"
	"fmt"
	"os"
)

// Handle logs an error and exits the program.
func Handle(err error) {
	if err != nil {
		var urlErr *URLError
		if errors.As(err, &urlErr) {
			fmt.Fprintf(os.Stderr, "Error at URL %s: %v\n", urlErr.URL, urlErr.Err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
