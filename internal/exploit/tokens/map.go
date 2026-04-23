package tokens

import "cwrap/internal/exploit/report"

func BuildCookieMap(ent report.ReportEntity, id *report.ReportIdentity) map[string]string {
	needed := make(map[string]bool, len(id.Cookies))
	for _, name := range id.Cookies {
		needed[name] = true
	}
	out := make(map[string]string)
	for _, sc := range ent.SessionCookies {
		if needed[sc.Name] {
			out[sc.Name] = sc.Value
		}
	}
	return out
}
