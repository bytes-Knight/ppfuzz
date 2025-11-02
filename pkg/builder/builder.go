package builder

import "net/url"

// The payload keys.
var payloads = []string{
	"__proto__.ppfuzz",
	"__proto__[ppfuzz]",
	"constructor.prototype.ppfuzz",
	"constructor[prototype][ppfuzz]",
}

const payloadValue = "reserved"

// Query generates a list of URLs with prototype pollution payloads.
func Query(targetURL string) []string {
	var urls []string
	for _, payloadKey := range payloads {
		u, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set(payloadKey, payloadValue)
		u.RawQuery = q.Encode()
		urls = append(urls, u.String())
	}
	return urls
}
