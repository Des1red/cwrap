package intent

func IsProfile(word string) (string, bool) {
	switch word {
	case "browser":
		return "firefox", true
	case "firefox", "chrome", "api", "curl":
		return word, true
	}
	return "", false
}

func IsContent(word string) (string, bool) {
	switch word {
	case "json", "xml", "form":
		return word, true
	}
	return "", false
}

func IsBooleanWord(word string) (bool, bool) {
	switch word {
	case "follow":
		return true, true
	case "nofollow":
		return false, true
	}
	return false, false
}
