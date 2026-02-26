package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"regexp"
	"strings"
)

var (
	reJWT = regexp.MustCompile(`\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	reAWS = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	rePEM = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----`)

	reAssign = regexp.MustCompile(`(?i)\b(api[_-]?key|client[_-]?secret|secret|token|bearer|authorization|private[_-]?key|password)\b\s*[:=]\s*["']([^"'\n\r]{6,})["']`)
)

func Learn(ent *knowledge.Entity, sourceURL string, body []byte) {

	if ent.Content.JSFindings == nil {
		ent.Content.JSFindings = make(map[string]int)
	}

	s := string(body)

	// ---- PEM ----
	if rePEM.FindStringIndex(s) != nil {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["pem"]++
		ent.Content.JSLeaks = append(ent.Content.JSLeaks,
			knowledge.JSLeak{
				Kind:   "pem",
				Source: sourceURL,
				Key:    "private_key",
				Value:  "-----BEGIN PRIVATE KEY-----",
			})
	}

	// ---- AWS ----
	aws := reAWS.FindAllString(s, -1)
	if len(aws) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["aws_key"] += len(aws)

		for i := 0; i < len(aws) && i < 5; i++ {
			ent.Content.JSLeaks = append(ent.Content.JSLeaks,
				knowledge.JSLeak{
					Kind:   "aws_key",
					Source: sourceURL,
					Key:    "access_key_id",
					Value:  aws[i],
				})
		}
	}

	// ---- JWT ----
	jwts := reJWT.FindAllString(s, -1)
	if len(jwts) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["jwt"] += len(jwts)

		for i := 0; i < len(jwts) && i < 5; i++ {
			ent.Content.JSLeaks = append(ent.Content.JSLeaks,
				knowledge.JSLeak{
					Kind:   "jwt",
					Source: sourceURL,
					Value:  jwts[i],
				})
		}
	}

	// ---- keyword assignments ----
	assigns := reAssign.FindAllStringSubmatch(s, -1)
	if len(assigns) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["keyword"] += len(assigns)

		for i := 0; i < len(assigns) && i < 5; i++ {
			key := strings.ToLower(assigns[i][1])
			val := assigns[i][2]

			// limit length to avoid insane dumps
			if len(val) > 200 {
				val = val[:200] + "..."
			}

			ent.Content.JSLeaks = append(ent.Content.JSLeaks,
				knowledge.JSLeak{
					Kind:   "keyword",
					Source: sourceURL,
					Key:    key,
					Value:  val,
				})
		}
	}

	// ---- Firebase config presence ----
	if strings.Contains(s, "authDomain") &&
		strings.Contains(s, "projectId") &&
		strings.Contains(s, "apiKey") {

		ent.Content.JSFindings["firebase"]++

		ent.Content.JSLeaks = append(ent.Content.JSLeaks,
			knowledge.JSLeak{
				Kind:   "firebase",
				Source: sourceURL,
				Key:    "firebase_config",
				Value:  "Firebase configuration block detected",
			})
	}
}
