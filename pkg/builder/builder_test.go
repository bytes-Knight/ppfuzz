package builder

import (
	"testing"
)

func TestQuery(t *testing.T) {
	urls := Query("http://example.com")
	if len(urls) != len(payloads) {
		t.Errorf("Expected %d URLs, but got %d", len(payloads), len(urls))
	}
}
