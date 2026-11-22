package contextbuilder

import (
	"regexp"
	"strings"
)

// Redact replaces sensitive patterns with [REDACTED:<type>] and returns
// the redacted text and the count of replacements made.
// Redaction is idempotent: Redact(Redact(x)) == Redact(x).
func Redact(text string) (redacted string, count int) {
	redacted = text

	// 1. PEM private key blocks (multi-line, highest priority)
	pemPattern := regexp.MustCompile(`(?i)-----BEGIN\s+(?:[A-Z0-9\s]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z0-9\s]+\s+)?PRIVATE\s+KEY-----`)
	redacted, c := replaceAll(redacted, pemPattern, "[REDACTED:PEM_PRIVATE_KEY]")
	count += c

	// 2. AWS access key IDs (AKIA...)
	akiaPattern := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	redacted, c = replaceAll(redacted, akiaPattern, "[REDACTED:AWS_ACCESS_KEY]")
	count += c

	// 3. GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
	githubPattern := regexp.MustCompile(`\b(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{36,}`)
	redacted, c = replaceAll(redacted, githubPattern, "[REDACTED:GITHUB_TOKEN]")
	count += c

	// 4. Slack tokens (xox*)
	slackPattern := regexp.MustCompile(`xox[abp]-[0-9a-zA-Z\-]{10,}`)
	redacted, c = replaceAll(redacted, slackPattern, "[REDACTED:SLACK_TOKEN]")
	count += c

	// 5. Google API keys (AIza...)
	googlePattern := regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	redacted, c = replaceAll(redacted, googlePattern, "[REDACTED:GOOGLE_API_KEY]")
	count += c

	// 6. Stripe live keys (sk_live_)
	stripePattern := regexp.MustCompile(`sk_live_[0-9a-zA-Z]{20,}`)
	redacted, c = replaceAll(redacted, stripePattern, "[REDACTED:STRIPE_KEY]")
	count += c

	// 7. JWTs (three base64url parts separated by dots, starting with eyJ)
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	redacted, c = replaceAll(redacted, jwtPattern, "[REDACTED:JWT_TOKEN]")
	count += c

	// 8. Bearer tokens (Bearer <token>)
	bearerPattern := regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	redacted, c = replaceAll(redacted, bearerPattern, "[REDACTED:BEARER_TOKEN]")
	count += c

	// 9. URLs with embedded credentials (scheme://user:pass@host)
	urlCredsPattern := regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^:/@\s]+:[^/@\s]+@[^\s/]+`)
	redacted, c = replaceAll(redacted, urlCredsPattern, "[REDACTED:URL_CREDENTIALS]")
	count += c

	// 10. Generic secret assignments (key=value or key:value)
	//     Key must contain: secret, token, password, passwd, pwd, api_key, apikey, auth, credential
	//     Value must be 8+ characters (quoted or unquoted)
	genericPattern := regexp.MustCompile(`(?i)(?:^|\s|[=:\[,])(?:secret|token|password|passwd|pwd|api_?key|apikey|auth|credential)[_-]?\w*\s*[:=]\s*(?:"([^"]*?)"|'([^']*?)'|([^\s,;\]\}]{8,}))`)
	redacted, c = replaceGenericSecrets(redacted, genericPattern)
	count += c

	return redacted, count
}

// replaceAll replaces every match with the marker. It keeps the same number of
// newlines as the text it replaced, so line numbers after the match never shift.
func replaceAll(text string, pattern *regexp.Regexp, replacement string) (string, int) {
	count := 0
	redacted := pattern.ReplaceAllStringFunc(text, func(match string) string {
		count++
		return replacement + strings.Repeat("\n", strings.Count(match, "\n"))
	})
	return redacted, count
}

// replaceGenericSecrets redacts the VALUE of key=value style secrets while
// keeping the key and separator. It also preserves newline counts.
func replaceGenericSecrets(text string, pattern *regexp.Regexp) (string, int) {
	matches := pattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text, 0
	}

	var sb strings.Builder
	lastEnd := 0
	count := 0

	for _, m := range matches {
		sb.WriteString(text[lastEnd:m[0]])

		// Where the secret value starts: the opening quote for quoted values
		// (groups 1 and 2), or the first character for unquoted values (group 3).
		valueStart, valueText := -1, ""
		switch {
		case m[2] != -1:
			valueStart, valueText = m[2]-1, text[m[2]:m[3]]
		case m[4] != -1:
			valueStart, valueText = m[4]-1, text[m[4]:m[5]]
		case m[6] != -1:
			valueStart, valueText = m[6], text[m[6]:m[7]]
		}

		// Already redacted (keeps Redact idempotent), or no value found: leave as is.
		if valueStart == -1 || strings.HasPrefix(valueText, "[REDACTED:") {
			sb.WriteString(text[m[0]:m[1]])
			lastEnd = m[1]
			continue
		}

		removed := text[valueStart:m[1]]
		sb.WriteString(text[m[0]:valueStart])
		sb.WriteString("[REDACTED:SECRET]")
		sb.WriteString(strings.Repeat("\n", strings.Count(removed, "\n")))

		lastEnd = m[1]
		count++
	}

	sb.WriteString(text[lastEnd:])
	return sb.String(), count
}
