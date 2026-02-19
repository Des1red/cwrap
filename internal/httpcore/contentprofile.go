package httpcore

import "cwrap/internal/model"

func getContentProfileHeaders(profile string) []model.Header {
	switch profile {

	case "json":
		return []model.Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Accept", Value: "application/json"},
		}

	case "form":
		return []model.Header{
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
		}

	case "xml":
		return []model.Header{
			{Name: "Content-Type", Value: "application/xml"},
			{Name: "Accept", Value: "application/xml"},
		}
	}
	return nil
}
