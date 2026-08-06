package jsintel

import (
	"cwrap/internal/recon/jsintel/common"
	"cwrap/internal/recon/knowledge"
	"strings"
)

func learnSecrets(
	k *knowledge.Knowledge,
	ent *knowledge.Entity,
	sourceURL,
	source string,
) {
	if common.RePEM.FindStringIndex(source) != nil {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["pem"]++
		common.AppendLeak(
			ent,
			"pem",
			sourceURL,
			"private_key",
			"-----BEGIN PRIVATE KEY-----",
		)
	}

	awsKeys := common.ReAWS.FindAllString(source, -1)
	if len(awsKeys) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["aws_key"] += len(awsKeys)

		for index := 0; index < len(awsKeys) && index < 5; index++ {
			common.AppendLeak(
				ent,
				"aws_key",
				sourceURL,
				"access_key_id",
				awsKeys[index],
			)
		}
	}

	jwts := common.ReJWT.FindAllString(source, -1)
	if len(jwts) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["jwt"] += len(jwts)

		for index := 0; index < len(jwts) && index < 5; index++ {
			common.AppendLeak(
				ent,
				"jwt",
				sourceURL,
				"",
				jwts[index],
			)
		}
	}

	assignments := common.ReAssign.FindAllStringSubmatch(source, -1)
	if len(assignments) > 0 {
		ent.Tag(knowledge.SigSensitiveKeyword)
		ent.Content.JSFindings["keyword"] += len(assignments)

		for index := 0; index < len(assignments) && index < 5; index++ {
			key := strings.ToLower(assignments[index][1])
			value := common.Redact(assignments[index][2], 200)

			common.AppendLeak(
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

		common.AppendLeak(
			ent,
			"firebase",
			sourceURL,
			"firebase_config",
			"Firebase configuration block detected",
		)
	}

	emails := common.ReEmail.FindAllString(source, -1)
	if len(emails) == 0 {
		return
	}

	ent.Content.JSFindings["email"] += len(emails)

	for _, email := range emails {
		common.AppendLeak(
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
