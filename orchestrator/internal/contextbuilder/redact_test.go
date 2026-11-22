package contextbuilder

import (
	"strings"
	"testing"
)

// PEM markers are built from pieces so the literal header never appears in source.
const (
	pemBegin    = "-----BEGIN RSA PRIVATE " + "KEY-----"
	pemEnd      = "-----END RSA PRIVATE " + "KEY-----"
	pemFakeBody = "NOT-A-REAL-KEY-BODY-FOR-TESTING"
)

func TestRedactPEMPrivateKey(t *testing.T) {
	// Build a secret at runtime (no literal PEM in source)
	secret := strings.Join([]string{pemBegin, pemFakeBody, pemEnd}, "\n")

	text := "Here is a key:\n" + secret + "\nEnd of key"
	redacted, count := Redact(text)

	if count != 1 {
		t.Errorf("expected 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, pemFakeBody) {
		t.Error("key material should be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED:PEM_PRIVATE_KEY]") {
		t.Error("should contain redaction marker")
	}
}

func TestRedactAWSKey(t *testing.T) {
	// Build AWS key at runtime
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	text := "AWS key: " + secret + " in config"
	redacted, count := Redact(text)

	if count != 1 {
		t.Errorf("expected 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, "ABCDEFGHIJKLMNOP") {
		t.Error("key should be redacted")
	}
	if !strings.Contains(redacted, "[REDACTED:AWS_ACCESS_KEY]") {
		t.Error("should contain redaction marker")
	}
}

func TestRedactGitHubToken(t *testing.T) {
	// Build GitHub token at runtime
	secret := "ghp_" + "1234567890123456789012345678901234"
	text := "Token: " + secret
	redacted, count := Redact(text)

	if count != 1 {
		t.Errorf("expected 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, "1234567890123456789012345678901234") {
		t.Error("token should be redacted")
	}
}

func TestRedactJWT(t *testing.T) {
	// Built from pieces so no JWT-shaped literal exists in source.
	jwtHeader := "eyJ" + "hbGciOiJIUzI1NiJ9"
	jwtPayload := "eyJ" + "zdWIiOiJ0ZXN0In0"
	jwtSig := "ZmFrZXNpZ25hdHVyZWZvcnRlc3Rvbmx5"
	secret := jwtHeader + "." + jwtPayload + "." + jwtSig

	// No "Bearer" prefix, so the JWT rule itself is what gets tested.
	text := "const t = '" + secret + "'"
	redacted, count := Redact(text)

	if count < 1 {
		t.Errorf("expected at least 1 redaction, got %d", count)
	}
	for _, part := range []string{jwtHeader, jwtPayload, jwtSig} {
		if strings.Contains(redacted, part) {
			t.Errorf("JWT part %q should be redacted", part)
		}
	}
	if !strings.Contains(redacted, "[REDACTED:") {
		t.Error("expected a [REDACTED:...] marker")
	}
}

func TestRedactBearerToken(t *testing.T) {
	// Build bearer token
	secret := "abc123def456ghi789jkl"
	text := "Authorization: Bearer " + secret
	redacted, count := Redact(text)

	if count < 1 {
		t.Errorf("expected at least 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, secret) {
		t.Error("bearer token should be redacted")
	}
}

func TestRedactURLCredentials(t *testing.T) {
	text := "Database URL: postgres://admin:secretpassword123@localhost:5432/mydb"
	redacted, count := Redact(text)

	if count != 1 {
		t.Errorf("expected 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, "secretpassword123") {
		t.Error("credentials should be redacted")
	}
}

func TestRedactGenericSecretAssignment(t *testing.T) {
	text := "api_key = 'thisIsASecretKeyWith8Chars'"
	redacted, count := Redact(text)

	if count != 1 {
		t.Errorf("expected 1 redaction, got %d", count)
	}
	if strings.Contains(redacted, "thisIsASecretKeyWith8Chars") {
		t.Error("secret value should be redacted")
	}
}

func TestRedactionIdempotent(t *testing.T) {
	secret := "AKIA" + "ABCDEFGHIJKLMNOP"
	text := "AWS key: " + secret

	redacted1, _ := Redact(text)
	redacted2, _ := Redact(redacted1)

	if redacted1 != redacted2 {
		t.Error("redaction should be idempotent")
	}
}

func TestRedactPEMBlockOutsideWindow(t *testing.T) {
	// A PEM block whose BEGIN line is outside the window
	// but whose body lines would be inside without redaction first
	fullKey := strings.Join([]string{pemBegin, pemFakeBody, pemEnd}, "\n")

	text := fullKey + "\n" + "some code line"
	redacted, _ := Redact(text)

	if strings.Contains(redacted, pemFakeBody) {
		t.Error("key material should be fully redacted")
	}
}

func TestOrdinaryCodeUnchanged(t *testing.T) {
	text := "fmt.Println(\"Hello, World!\")\nvar x = 42"
	redacted, count := Redact(text)

	if count != 0 {
		t.Errorf("ordinary code should not be redacted, got %d redactions", count)
	}
	if redacted != text {
		t.Error("ordinary code should be unchanged")
	}
}

func TestMultipleSecretsInText(t *testing.T) {
	secret1 := "AKIA" + "ABCDEFGHIJKLMNOP"
	secret2 := "ghp_" + "123456789012345678901234567890123456" // 36+ chars
	text := "Keys: " + secret1 + " and " + secret2

	redacted, count := Redact(text)

	if count < 2 {
		t.Errorf("expected at least 2 redactions, got %d", count)
	}
	if strings.Contains(redacted, "ABCDEFGHIJKLMNOP") || strings.Contains(redacted, "123456789012345678901234567890123456") {
		t.Error("both secrets should be redacted")
	}
}

func TestRedactSecretWithSeparatorInsideValue(t *testing.T) {
	cases := []struct {
		in    string
		leaks []string
	}{
		{`password = "abc=defghijkl"`, []string{"abc", "defghijkl"}},
		{`token: "dGVzdHRlc3R0ZXN0=="`, []string{"dGVzdHRl", "ZXN0"}},
		{`api_key = 'part1:part2-value'`, []string{"part1", "part2"}},
		{`secret=abc:defghijkl`, []string{"abc", "defghijkl"}},
	}
	for _, c := range cases {
		out, count := Redact(c.in)
		if count != 1 {
			t.Errorf("%q: expected 1 redaction, got %d (output %q)", c.in, count, out)
		}
		for _, leak := range c.leaks {
			if strings.Contains(out, leak) {
				t.Errorf("%q: %q leaked into %q", c.in, leak, out)
			}
		}
		again, _ := Redact(out)
		if again != out {
			t.Errorf("%q: not idempotent: %q then %q", c.in, out, again)
		}
	}
}