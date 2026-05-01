package linkutil

import (
	"net"
	"net/url"
	"strings"
)

func SameSite(base, target *url.URL) bool {
	if base.Host == target.Host {
		return true
	}
	return rootDomain(base.Host) != "" && rootDomain(base.Host) == rootDomain(target.Host)
}

func rootDomain(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
