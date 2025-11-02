package errors

import "fmt"

// URLError is a custom error type that includes the URL that caused the error.
type URLError struct {
	URL string
	Err error
}

// Error returns the error message.
func (e *URLError) Error() string {
	return fmt.Sprintf("error at URL %s: %v", e.URL, e.Err)
}

// Unwrap returns the wrapped error.
func (e *URLError) Unwrap() error {
	return e.Err
}
