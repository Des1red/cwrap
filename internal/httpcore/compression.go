package httpcore

func SupportsCompression(profile string) bool {
	switch profile {
	case "firefox", "chrome", "api":
		return true
	default:
		return false
	}
}
