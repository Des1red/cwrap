package httpcore

import (
	"cwrap/internal/model"
	"strings"
)

func hasAuthorizationHeader(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Authorization") {
			return true
		}
	}
	return false
}

func hasAcceptEncoding(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Accept-Encoding") {
			return true
		}
	}
	return false
}

func hasContentType(headers []model.Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			return true
		}
	}
	return false
}
