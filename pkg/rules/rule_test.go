// Tests for what a rule is and what makes one valid, plus the helpers the
// other test files in this package build on.

package rules

import (
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// testRule is a minimal valid single-pattern HTTP rule, used as a base that
// individual tests adjust. It is not a real provider; the tests point it at a
// local server.
func testRule() Rule {
	return Rule{
		Type:        detector_typepb.DetectorType_SendGrid,
		Description: "test rule",
		Keywords:    []string{"tk_"},
		Patterns: []Pattern{
			{Name: "key", Regex: `tk_[a-z0-9]{10}`},
		},
		Verify: HTTP{
			URL:           "https://example.invalid/",
			Headers:       map[string]string{"Authorization": "Bearer {key}"},
			ValidStatus:   StatusCodes{200},
			InvalidStatus: StatusCodes{401},
		},
	}
}

// testSecret is a value the base rule's pattern matches.
const testSecret = "tk_abcdefghij"

// rulePointedAt returns the base rule with its verifier aimed at a test server
// instead of a real provider, applying any further tweak a test needs.
func rulePointedAt(url string, tweak func(*HTTP)) Rule {
	rule := testRule()
	verifier := rule.Verify.(HTTP)
	verifier.URL = url
	if tweak != nil {
		tweak(&verifier)
	}
	rule.Verify = verifier
	return rule
}

func TestValidateAcceptsWellFormedRule(t *testing.T) {
	if err := testRule().Validate(); err != nil {
		t.Fatalf("well-formed rule failed to validate: %v", err)
	}
}

func TestValidateCatchesMistakes(t *testing.T) {
	invalidRule := Rule{
		Type:        detector_typepb.DetectorType_SendGrid,
		Description: "x",
		Keywords:    []string{"x"}, // too short
		Patterns: []Pattern{
			{Name: "key", Regex: `x`},
		},
		Verify: HTTP{URL: "https://x/{nope}", ValidStatus: StatusCodes{200}, InvalidStatus: StatusCodes{200}},
	}
	err := invalidRule.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{
		"shorter than 2 characters",
		"references unknown pattern {nope}",
		"both ValidStatus and InvalidStatus",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

// A regex is source text on a rule and is compiled when the detector is built,
// so a mistake in one has to be caught here rather than at package init.
func TestValidateRejectsUncompilableRegex(t *testing.T) {
	rule := testRule()
	rule.Patterns[0].Regex = `tk_([a-z`
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "does not compile") {
		t.Errorf("expected a compile error, got %v", err)
	}
}

// A prefix word outside the rule's keywords can never fire: the engine only
// hands a rule chunks that hold a keyword, so the pattern never sees text
// introduced by that word alone.
func TestValidateRejectsPrefixOutsideKeywords(t *testing.T) {
	rule := testRule()
	rule.Patterns[0].Prefix = []string{"somethingelse"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "not one of the rule's keywords") {
		t.Errorf("expected a prefix error, got %v", err)
	}
}

// TestPrefixRequiresTheKeywordNearby checks the prefix is really built into the
// expression: the same value matches with the word in front of it and not
// without.
func TestPrefixRequiresTheKeywordNearby(t *testing.T) {
	rule := testRule()
	rule.Keywords = []string{"tk_", "widget"}
	rule.Patterns[0].Regex = `(tk_[a-z0-9]{10})`
	rule.Patterns[0].Prefix = []string{"widget"}

	compiled, problems := rule.compile()
	if len(problems) > 0 {
		t.Fatalf("compiling: %v", problems)
	}

	if got := findUniqueCaptures(compiled[0], "widget key = "+testSecret); len(got) != 1 || got[0] != testSecret {
		t.Errorf("with the keyword in front: got %v, want [%s]", got, testSecret)
	}
	if got := findUniqueCaptures(compiled[0], "key = "+testSecret); len(got) != 0 {
		t.Errorf("without the keyword: got %v, want nothing", got)
	}
	// Far enough away is the same as absent. See detectors.PrefixRegex.
	if got := findUniqueCaptures(compiled[0], "widget "+strings.Repeat("x", 60)+" "+testSecret); len(got) != 0 {
		t.Errorf("with the keyword too far away: got %v, want nothing", got)
	}
}

// Without a capture group the value reported would start at the keyword, so
// the rule is rejected rather than quietly storing secrets with a prefix glued
// to the front.
func TestValidateRejectsPrefixWithoutCaptureGroup(t *testing.T) {
	rule := testRule()
	rule.Keywords = []string{"tk_", "widget"}
	rule.Patterns[0].Prefix = []string{"widget"}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "captures its whole match") {
		t.Errorf("expected a capture-group error, got %v", err)
	}
}

// A negative span would be read as "no override" by chunkSpan and quietly
// give the rule the default, hiding the mistake.
func TestValidateRejectsNegativeChunkSpan(t *testing.T) {
	rule := testRule()
	rule.MaxChunkSpan = -1
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "MaxChunkSpan is negative") {
		t.Errorf("expected a negative-span error, got %v", err)
	}
}

func TestValidateRequiresSecretIDForMultiPattern(t *testing.T) {
	rule := testRule()
	rule.Patterns = append(rule.Patterns, Pattern{Name: "id", Regex: `id_[a-z]{6}`})
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "no SecretID") {
		t.Errorf("expected a missing-SecretID error, got %v", err)
	}
}

// Leaving FullSecretID empty on a multi-pattern rule is a supported choice,
// not a mistake: every combination sharing a SecretID collapses into one
// finding.
func TestValidateAllowsMultiPatternWithoutFullSecretID(t *testing.T) {
	rule := testRule()
	rule.Patterns = append(rule.Patterns, Pattern{Name: "id", Regex: `id_[a-z]{6}`})
	rule.SecretID = "{key}"
	if err := rule.Validate(); err != nil {
		t.Errorf("multi-pattern rule without FullSecretID should be valid, got %v", err)
	}
}

// TestValidateRejectsDistinctCapturesWithOnePattern guards against a rule that
// sets the flag expecting it to do something it cannot.
func TestValidateRejectsDistinctCapturesWithOnePattern(t *testing.T) {
	rule := testRule()
	rule.DistinctCaptures = true
	if err := rule.Validate(); err == nil {
		t.Fatal("expected an error for DistinctCaptures with a single pattern")
	}
}

// Validate reads every body field as a template too, so a misspelt pattern
// name in a body is caught at startup rather than sending an empty value.
func TestValidateChecksBodyFields(t *testing.T) {
	rule := testRule()
	rule.Verify = HTTP{
		Method:        "POST",
		URL:           "https://example.invalid/",
		Body:          map[string]string{"service": "list", "key": "{key}"},
		ValidStatus:   StatusCodes{200},
		InvalidStatus: StatusCodes{401},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("braces in a JSON body were treated as pattern names: %v", err)
	}

	rule.Verify = HTTP{
		URL:           "https://example.invalid/",
		Body:          map[string]string{"key": "{ke}"},
		ValidStatus:   StatusCodes{200},
		InvalidStatus: StatusCodes{401},
	}
	if err := rule.Validate(); err == nil {
		t.Fatal("a misspelt pattern name went unnoticed")
	}
}

// TestValidateRejectsUnsafeURLTemplates guards the two places a captured value
// must never reach: the server name, and the query string.
func TestValidateRejectsUnsafeURLTemplates(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"host", "https://{key}.example.invalid/"},
		{"query", "https://example.invalid/?token={key}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := rulePointedAt(tc.url, nil)
			if err := rule.Validate(); err == nil {
				t.Fatalf("URL %q should not validate", tc.url)
			}
		})
	}
}

func TestNewPanicsOnInvalidRule(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New did not panic on an invalid rule")
		}
	}()
	New(Rule{}, nil)
}
