package report

import (
	"cwrap/internal/recon/knowledge"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func writeAbnormalResponses(
	k *knowledge.Knowledge,
	reportPath string,
) (string, int, error) {
	if k == nil {
		return "", 0, fmt.Errorf("nil knowledge")
	}

	responses := collectAbnormalResponses(k)
	if len(responses) == 0 {
		return "", 0, nil
	}

	reportExt := filepath.Ext(reportPath)
	reportBase := strings.TrimSuffix(reportPath, reportExt)
	dir := reportBase + "_abnormal_responses"

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", 0, fmt.Errorf(
			"create abnormal response directory: %w",
			err,
		)
	}

	for i, response := range responses {
		name := abnormalResponseFilename(i+1, response)
		path := filepath.Join(dir, name)

		if err := os.WriteFile(path, response.Body, 0o600); err != nil {
			return dir, i, fmt.Errorf(
				"write abnormal response %q: %w",
				path,
				err,
			)
		}
	}

	return dir, len(responses), nil
}

func collectAbnormalResponses(
	k *knowledge.Knowledge,
) []knowledge.AbnormalResponse {
	urls := sortedEntityURLs(k)

	var out []knowledge.AbnormalResponse

	for _, rawURL := range urls {
		ent := k.Entities[rawURL]
		if ent == nil {
			continue
		}

		out = append(out, ent.AbnormalResponses...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].Identity != out[j].Identity {
			return out[i].Identity < out[j].Identity
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})

	return out
}

func abnormalResponseFilename(
	index int,
	response knowledge.AbnormalResponse,
) string {
	return fmt.Sprintf(
		"%03d_%s_%s_%d.response",
		index,
		sanitizeResponseFilenamePart(response.Method),
		sanitizeResponseFilenamePart(response.Identity),
		response.Status,
	)
}

func sanitizeResponseFilenamePart(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))

	var b strings.Builder
	b.Grow(len(value))

	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}

	result := strings.Trim(b.String(), "_")
	if result == "" {
		return "unknown"
	}

	if len(result) > 60 {
		return result[:60]
	}

	return result
}
