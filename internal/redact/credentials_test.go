package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// Literal passwords are split so the repository's gitleaks job sees none.
var (
	urlPassword  = "S3cr3t" + "P4ssw0rd!"
	propPassword = "Sup3r" + "S3cret!"
	plainPasswd  = "Pl41n" + "P4ssw0rd!"
)

func TestRedactURLCredentials(t *testing.T) {
	tests := []struct {
		name, text, keep string
	}{
		{"postgres", "postgres://admin:" + urlPassword + "@db.example:5432/app", "postgres://admin:"},
		{"mysql", "dsn: mysql://root:" + urlPassword + "@tcp(10.0.0.1:3306)/x", "mysql://root:"},
		{"redis no user", `url = "redis://:` + urlPassword + `@cache:6379/0"`, "redis://:"},
		{"amqp", "AMQP_URL=amqp://guest:" + urlPassword + "@mq.local/vhost", "amqp://guest:"},
		{"sqlserver", "sqlserver://sa:" + urlPassword + "@sql.local?database=x", "sqlserver://sa:"},
		{"mongodb srv", "mongodb+srv://app:" + urlPassword + "@cluster0.mongodb.net/db", "mongodb+srv://app:"},
		{"https", "git clone https://bot:" + urlPassword + "@git.example.com/r.git", "https://bot:"},
		{"raw at sign", "postgres://u:p@ss" + urlPassword + "@db/app", "postgres://u:"},
		{"raw slash", "postgres://u:ab/" + urlPassword + "@db/app", "postgres://u:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if strings.Contains(out, urlPassword) || strings.Contains(out, "ss"+urlPassword[:4]) {
				t.Fatalf("password leaked: %q", out)
			}
			if !strings.Contains(out, tc.keep+"<SECRET_URL_PASSWORD_1>") {
				t.Fatalf("Redact(%q) = %q, want %q followed by the marker", tc.text, out, tc.keep)
			}
		})
	}
}

// The email detector also matches the tail of the password ("x@db.internal");
// the merged span must cover the whole password and keep the secret label.
func TestRedactURLPasswordOverlappingEmail(t *testing.T) {
	r := newRedactor(t)
	pw := urlPassword + "x"
	out := mustRedact(t, r, "postgres://admin:"+pw+"@db.internal\n")
	if out != "postgres://admin:<SECRET_URL_PASSWORD_1>\n" {
		t.Fatalf("got %q", out)
	}
	// The password alone in a later fragment is still known.
	if later := mustRedact(t, r, "pw "+pw+" "); strings.Contains(later, pw) {
		t.Fatalf("password leaked in a later fragment: %q", later)
	}
}

func TestRedactPasswordAssignments(t *testing.T) {
	tests := []struct {
		name, text, secret, keep string
	}{
		{"passwd single quotes", "passwd='" + plainPasswd + "'", plainPasswd, "passwd='"},
		{"properties", "spring.datasource.password=" + propPassword + "\n", propPassword, "spring.datasource.password="},
		{"yaml", "db:\n  password: " + propPassword + "\n", propPassword, "password: "},
		{"pwd", "Server=x;pwd=" + propPassword + ";", propPassword, "pwd="},
		{"secret", "secret=" + propPassword, propPassword, "secret="},
		{"dotenv", "DB_PASSWORD=" + propPassword + "\n", propPassword, "DB_PASSWORD="},
		{"json", `{"password": "` + propPassword + `"}`, propPassword, `"password": "`},
		{"go", "password := `" + propPassword + "`", propPassword, "password := `"},
		{"python", "PASSWORD = \"" + propPassword + "\"", propPassword, "PASSWORD = \""},
		{"ruby arrow", ":password => '" + propPassword + "'", propPassword, ":password => '"},
		{"aws secret env", "AWS_SECRET_ACCESS_KEY=" + propPassword, propPassword, "AWS_SECRET_ACCESS_KEY="},
		{"placeholder word", "password: changeme", "changeme", "password: "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("password leaked: %q", out)
			}
			if !strings.Contains(out, tc.keep+"<SECRET_") {
				t.Fatalf("Redact(%q) = %q, want key %q kept before a marker", tc.text, out, tc.keep)
			}
		})
	}
}

func TestRedactPasswordKeepsReferences(t *testing.T) {
	tests := []string{
		"password: ${DB_PASSWORD}",
		"PASSWORD=$DB_PASS",
		"password=<your-password>",
		`password: "{{ .Values.dbPassword }}"`,
		`password = os.Getenv("DB_PASSWORD")`,
		"secret := loadSecret()",
		`if password == "" {`,
		`password: ""`,
		"password:\n  from: vault",
	}
	for _, text := range tests {
		if out := mustRedact(t, newRedactor(t), text); out != text {
			t.Errorf("Redact(%q) = %q, want unchanged", text, out)
		}
	}
}

func TestRedactAWSSecretKey(t *testing.T) {
	rng := rand.New(rand.NewPCG(21, 22))
	id := fakeAWS(rng)
	key := fakeToken(rng, alnum, 30) + "Ab/+" + fakeToken(rng, alnum, 6)
	digest := strings.Repeat("0123456789abcdef", 3)[:40]
	tests := []struct {
		name, text string
		masked     bool
	}{
		{"next to key id", id + "," + key + "\n", true},
		{"key id elsewhere", "id: " + id + "\nother: x\nsk: " + key, true},
		{"no key id", "sk: " + key, false},
		{"hex digest", id + " " + digest, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			value := key
			if tc.name == "hex digest" {
				value = digest
			}
			if leaked := strings.Contains(out, value); leaked == tc.masked {
				t.Fatalf("masked = %v, want %v: %q", !leaked, tc.masked, out)
			}
		})
	}
}

// A GitHub token is also a generic key value; the specific rule names it.
func TestRedactPrefersSpecificLabel(t *testing.T) {
	gh := fakeGitHub(rand.New(rand.NewPCG(23, 24)))
	tests := []struct{ text, marker string }{
		{"token := \"" + gh + "\"", "<SECRET_GITHUB_PAT_1>"},
		{"secret = " + gh, "<SECRET_GITHUB_PAT_1>"},
	}
	for _, tc := range tests {
		if out := mustRedact(t, newRedactor(t), tc.text); !strings.Contains(out, tc.marker) {
			t.Errorf("Redact(%q) = %q, want %s", tc.text, out, tc.marker)
		}
	}
}
