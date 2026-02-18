package builder

import (
	"cwrap/internal/model"
	"strings"
)

func getProfileHeaders(profile string) []model.Header {
	switch profile {

	case "firefox":
		return []model.Header{
			{Name: "User-Agent", Value: "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{Name: "Accept-Language", Value: "en-US,en;q=0.5"},
			{Name: "Accept-Encoding", Value: "gzip, deflate, br"},
			{Name: "Connection", Value: "keep-alive"},
			{Name: "Upgrade-Insecure-Requests", Value: "1"},
			{Name: "Sec-Fetch-Dest", Value: "document"},
			{Name: "Sec-Fetch-Mode", Value: "navigate"},
			{Name: "Sec-Fetch-Site", Value: "none"},
			{Name: "Sec-Fetch-User", Value: "?1"},
		}

	case "chrome":
		return []model.Header{
			{Name: "User-Agent", Value: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{Name: "Accept-Language", Value: "en-US,en;q=0.9"},
			{Name: "Accept-Encoding", Value: "gzip, deflate, br"},
			{Name: "Connection", Value: "keep-alive"},
			{Name: "Upgrade-Insecure-Requests", Value: "1"},
			{Name: "Sec-Fetch-Dest", Value: "document"},
			{Name: "Sec-Fetch-Mode", Value: "navigate"},
			{Name: "Sec-Fetch-Site", Value: "none"},
			{Name: "Sec-Fetch-User", Value: "?1"},
			{Name: "sec-ch-ua", Value: `"Chromium";v="121", "Not A(Brand";v="99"`},
			{Name: "sec-ch-ua-mobile", Value: "?0"},
			{Name: "sec-ch-ua-platform", Value: `"Linux"`},
		}

	case "api":
		return []model.Header{
			{Name: "Accept", Value: "application/json"},
			{Name: "Content-Type", Value: "application/json"},
		}

	case "curl":
		return []model.Header{
			{Name: "User-Agent", Value: "curl/8.0"},
			{Name: "Accept", Value: "*/*"},
		}

	default:
		return nil
	}
}

func mergeHeaders(profile, user []model.Header) []model.Header {
	final := make([]model.Header, 0, len(profile)+len(user))

	for _, p := range profile {
		overridden := false
		for _, u := range user {
			if equalHeader(p.Name, u.Name) {
				overridden = true
				break
			}
		}
		if !overridden {
			final = append(final, p)
		}
	}

	final = append(final, user...)
	return final
}

func equalHeader(a, b string) bool {
	return strings.EqualFold(a, b)
}
