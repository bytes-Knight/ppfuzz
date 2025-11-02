package errors

import (
	"fmt"
	"os"
)

// Handle logs an error and exits the program.
func Handle(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
