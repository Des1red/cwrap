package intent

func isProfile(word string) (string, bool) {
	switch word {
	case "browser":
		return "firefox", true
	case "firefox", "chrome", "api", "curl":
		return word, true
	}
	return "", false
}

func isContent(word string) (string, bool) {
	switch word {
	case "json", "xml", "form":
		return word, true
	}
	return "", false
}

func isBooleanWord(word string) (string, bool) {
	switch word {
	case "follow":
		return "follow", true
	case "nofollow":
		return "nofollow", true
	case "csrf":
		return "csrf", true
	case "auto-cookie":
		return "auto-cookie", true
	}
	return "", false
}

func resolveSemanticWord(word string) (Token, bool) {

	if name, ok := isBooleanWord(word); ok {
		return Token{
			Type: TokenFlag,
			Raw:  "--" + name,
		}, true
	}

	return Token{}, false
}
