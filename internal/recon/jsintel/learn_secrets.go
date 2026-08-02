package jsintel

import (
	"cwrap/internal/recon/knowledge"
	"strings"
)

func learnSecrets(
	k *knowledge.Knowledge,
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	if rePEM.FindStringIndex(source) != nil {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["pem"]++
		appendLeak(
			ent,
			"pem",
			sourceURL,
			"private_key",
			"-----BEGIN PRIVATE KEY-----",
		)
	}

	awsKeys := reAWS.FindAllString(source, -1)
	if len(awsKeys) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["aws_key"] += len(awsKeys)

		for index := 0; index < len(awsKeys) && index < 5; index++ {
			appendLeak(
				ent,
				"aws_key",
				sourceURL,
				"access_key_id",
				awsKeys[index],
			)
		}
	}

	jwts := reJWT.FindAllString(source, -1)
	if len(jwts) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["jwt"] += len(jwts)

		for index := 0; index < len(jwts) && index < 5; index++ {
			appendLeak(
				ent,
				"jwt",
				sourceURL,
				"",
				jwts[index],
			)
		}
	}

	assignments := reAssign.FindAllStringSubmatch(source, -1)
	if len(assignments) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["keyword"] += len(assignments)

		for index := 0; index < len(assignments) && index < 5; index++ {
			key := strings.ToLower(assignments[index][1])
			value := redact(assignments[index][2], 200)

			appendLeak(
				ent,
				"keyword",
				sourceURL,
				key,
				value,
			)
		}
	}

	if strings.Contains(source, "authDomain") &&
		strings.Contains(source, "projectId") &&
		strings.Contains(source, "apiKey") {
		ent.Content.JSFindings["firebase"]++

		appendLeak(
			ent,
			"firebase",
			sourceURL,
			"firebase_config",
			"Firebase configuration block detected",
		)
	}

	emails := reEmail.FindAllString(source, -1)
	if len(emails) == 0 {
		return
	}

	ent.Content.JSFindings["email"] += len(emails)

	for _, email := range emails {
		appendLeak(
			ent,
			"email",
			sourceURL,
			"",
			email,
		)

		if k != nil {
			k.AddEmail(email)
		}
	}
}
