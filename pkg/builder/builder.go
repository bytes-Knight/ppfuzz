package builder

import "net/url"

var payloads = []string{
	"__proto__[test]=test",
	"constructor[prototype][test]=test",
	"constructor.prototype.test=test",
}

// Query generates a list of URLs with prototype pollution payloads.
func Query(targetURL string) []string {
	var urls []string
	for _, payload := range payloads {
		u, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Add(payload, "")
		u.RawQuery = q.Encode()
		urls = append(urls, u.String())
	}
	return urls
}
