package fuzzer

import (
	"net/url"
	"testing"
)

func TestShowPotential(t *testing.T) {
	// A URL with an existing query parameter
	targetURL := "http://example.com?param1=value1"
	// The gadget to test
	gadget := "Adobe Dynamic Tag Management"
	// The expected query parameter from the gadget
	expectedParam := "__proto__[src]"

	// Call the function to get the generated URLs
	urls := ShowPotential(targetURL, gadget)

	// Check if any URL was generated
	if len(urls) == 0 {
		t.Fatalf("No URLs were generated")
	}

	// The first URL should be the one we are interested in
	generatedURL := urls[0]

	// Parse the generated URL
	u, err := url.Parse(generatedURL)
	if err != nil {
		t.Fatalf("Failed to parse the generated URL: %v", err)
	}

	// Get the query parameters from the generated URL
	queryParams := u.Query()

	// Check if the original query parameter is preserved
	if queryParams.Get("param1") != "value1" {
		t.Errorf("Expected the original query parameter 'param1' to be preserved, but it was not")
	}

	// Check if the new query parameter is added
	if _, ok := queryParams[expectedParam]; !ok {
		t.Errorf("Expected the new query parameter '%s' to be added, but it was not. Query: %s", expectedParam, u.RawQuery)
	}
}

func TestShowPotentialJQuery(t *testing.T) {
	// A URL with an existing query parameter
	targetURL := "http://example.com?param1=value1"
	// The gadget to test
	gadget := "jQuery"
	// The expected query parameters from the gadget
	expectedParams1 := []string{"__proto__[context]", "__proto__[jquery]"}
	expectedParams2 := []string{"__proto__[url][]", "__proto__[dataType]"}

	// Call the function to get the generated URLs
	urls := ShowPotential(targetURL, gadget)

	// Check if any URL was generated
	if len(urls) != 2 {
		t.Fatalf("Expected 2 URLs to be generated, but got %d", len(urls))
	}

	// Check the first URL for its specific parameters
	u1, _ := url.Parse(urls[0])
	q1 := u1.Query()
	if q1.Get("param1") != "value1" {
		t.Errorf("Expected the original query parameter 'param1' to be preserved in the first URL, but it was not")
	}
	for _, param := range expectedParams1 {
		if _, ok := q1[param]; !ok {
			t.Errorf("Expected the query parameter '%s' to be in the first URL, but it was not. Query: %s", param, u1.RawQuery)
		}
	}
	for _, param := range expectedParams2 {
		if _, ok := q1[param]; ok {
			t.Errorf("Expected the query parameter '%s' not to be in the first URL, but it was. Query: %s", param, u1.RawQuery)
		}
	}

	// Check the second URL for its specific parameters
	u2, _ := url.Parse(urls[1])
	q2 := u2.Query()
	if q2.Get("param1") != "value1" {
		t.Errorf("Expected the original query parameter 'param1' to be preserved in the second URL, but it was not")
	}
	for _, param := range expectedParams2 {
		if _, ok := q2[param]; !ok {
			t.Errorf("Expected the query parameter '%s' to be in the second URL, but it was not. Query: %s", param, u2.RawQuery)
		}
	}
	for _, param := range expectedParams1 {
		if _, ok := q2[param]; ok {
			t.Errorf("Expected the query parameter '%s' not to be in the second URL, but it was. Query: %s", param, u2.RawQuery)
		}
	}
}
