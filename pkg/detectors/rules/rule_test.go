package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
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
			{Name: "key", Regex: regexp.MustCompile(`tk_[a-z0-9]{10}`)},
		},
		Verify: HTTP{
			URL:     "https://example.invalid/",
			Headers: map[string]string{"Authorization": "Bearer {key}"},
			Valid:   Status{200},
			Invalid: Status{401},
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
			{Name: "key", Regex: regexp.MustCompile(`x`)},
		},
		Verify: HTTP{URL: "https://x/{nope}", Valid: Status{200}, Invalid: Status{200}},
	}
	err := invalidRule.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{
		"shorter than 2 characters",
		"references unknown pattern {nope}",
		"both Valid and Invalid",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestValidateRequiresRawForMultiPattern(t *testing.T) {
	rule := testRule()
	rule.Patterns = append(rule.Patterns, Pattern{Name: "id", Regex: regexp.MustCompile(`id_[a-z]{6}`)})
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "no Raw") {
		t.Errorf("expected a missing-Raw error, got %v", err)
	}
}

// Leaving RawV2 empty on a multi-pattern rule is a supported choice, not a
// mistake: it makes every combination sharing a Raw collapse into one finding.
func TestValidateAllowsMultiPatternWithoutRawV2(t *testing.T) {
	rule := testRule()
	rule.Patterns = append(rule.Patterns, Pattern{Name: "id", Regex: regexp.MustCompile(`id_[a-z]{6}`)})
	rule.Raw = "{key}"
	if err := rule.Validate(); err != nil {
		t.Errorf("multi-pattern rule without RawV2 should be valid, got %v", err)
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

func TestVerificationTriState(t *testing.T) {
	type want struct {
		verified bool
		hasErr   bool
	}
	cases := []struct {
		status int
		body   string
		want   want
	}{
		{200, `{"scopes":["mail.send","alerts.read"]}`, want{true, false}},
		{401, ``, want{false, false}}, // declared Invalid: definitive, no error
		{400, ``, want{false, true}},  // undeclared: unknown
		{429, ``, want{false, true}},
		{500, ``, want{false, true}},
	}

	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer tk_abcdefghij" {
				t.Errorf("header not interpolated, got %q", got)
			}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))

		rule := rulePointedAt(srv.URL, func(h *HTTP) {
			h.Extract = map[string]Extract{"scopes": {JSONField: "scopes", Join: ","}}
		})

		detector := New(rule, srv.Client())
		results, err := detector.FromData(context.Background(), true, []byte(testSecret))
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: %v", tc.status, err)
		}
		if len(results) != 1 {
			t.Fatalf("status %d: got %d results, want 1", tc.status, len(results))
		}
		result := results[0]
		if result.Verified != tc.want.verified || (result.VerificationError() != nil) != tc.want.hasErr {
			t.Errorf("status %d: verified=%v err=%v, want verified=%v hasErr=%v",
				tc.status, result.Verified, result.VerificationError(), tc.want.verified, tc.want.hasErr)
		}
		if tc.status == 200 && result.ExtraData["scopes"] != "mail.send,alerts.read" {
			t.Errorf("extraction failed: %v", result.ExtraData)
		}
	}
}

// A transport failure must be reported as unknown, never as invalid. The two
// are both unverified, and only the attached error separates "the provider
// rejected this key" from "we never got an answer".
func TestTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := srv.URL
	srv.Close() // nothing is listening on that port now

	rule := rulePointedAt(deadURL, nil)

	results, err := New(rule, http.DefaultClient).FromData(context.Background(), true, []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Verified || results[0].VerificationError() == nil {
		t.Errorf("transport failure must be unknown, got verified=%v err=%v",
			results[0].Verified, results[0].VerificationError())
	}
}

func TestVerificationErrorRedactsSecret(t *testing.T) {
	const secret = "tk_abcdefghij"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	rule := rulePointedAt(srv.URL, nil)

	results, _ := New(rule, srv.Client()).FromData(context.Background(), true, []byte(secret))
	if e := results[0].VerificationError(); e == nil || strings.Contains(e.Error(), secret) {
		t.Errorf("secret leaked into verification error: %v", e)
	}
}

func TestValidBodyContainsDowngradesToInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"unrelated":true}`))
	}))
	defer srv.Close()

	rule := rulePointedAt(srv.URL, func(h *HTTP) {
		h.ValidBodyContains = "ipAddress"
	})

	results, err := New(rule, srv.Client()).FromData(context.Background(), true, []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Verified {
		t.Error("a 200 without the expected body content must not verify")
	}
	if results[0].VerificationError() != nil {
		t.Error("a body-content mismatch is a definitive invalid, not unknown")
	}
}

// Optional interfaces must only be implemented when a rule asks for them: the
// engine reads them off the detector to size the chunk window it passes in.
func TestOptionalInterfacesAreOptional(t *testing.T) {
	plain := New(testRule(), nil)
	if _, ok := plain.(detectors.MultiPartCredentialProvider); ok {
		t.Error("plain rule must not implement MultiPartCredentialProvider")
	}
	if _, ok := plain.(detectors.Versioner); ok {
		t.Error("plain rule must not implement Versioner")
	}

	spanned := testRule()
	spanned.MaxCredentialSpan = 1024
	span := New(spanned, nil)
	p, ok := span.(detectors.MultiPartCredentialProvider)
	if !ok {
		t.Fatal("rule with MaxCredentialSpan must implement MultiPartCredentialProvider")
	}
	if p.MaxCredentialSpan() != 1024 {
		t.Errorf("span = %d, want 1024", p.MaxCredentialSpan())
	}

	versioned := testRule()
	versioned.Version = 2
	v, ok := New(versioned, nil).(detectors.Versioner)
	if !ok {
		t.Fatal("versioned rule must implement Versioner")
	}
	if v.Version() != 2 {
		t.Errorf("version = %d, want 2", v.Version())
	}
}

// Scanned data reaches outbound verification requests, so a captured value must
// not be able to forge a header or smuggle a query parameter.
func TestInjectionIsRejected(t *testing.T) {
	h := HTTP{
		URL:     "https://example.invalid/",
		Headers: map[string]string{"X-Key": "{key}"},
		Valid:   Status{200},
	}
	_, _, err := h.Verify(context.Background(),
		Creds{"key": "abc\r\nX-Admin: true"}, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "not a valid X-Key header") {
		t.Errorf("CRLF in a capture must be rejected, got %v", err)
	}

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	q := HTTP{URL: srv.URL, Query: map[string]string{"q": "{key}"}, Valid: Status{200}}
	if _, _, err := q.Verify(context.Background(), Creds{"key": "a&admin=1"}, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "a&admin=1" {
		t.Errorf("query value was not escaped as one parameter: %q", gotQuery)
	}
}

func TestNonHTTPSchemeRejected(t *testing.T) {
	h := HTTP{URL: "file:///etc/passwd", Valid: Status{200}}
	if _, _, err := h.Verify(context.Background(), Creds{}, http.DefaultClient); err == nil {
		t.Error("non-http scheme must be rejected")
	}
}

func TestFromDataCrossProduct(t *testing.T) {
	r := Rule{
		Type:        detector_typepb.DetectorType_SendGrid,
		Description: "multi-pattern test",
		Keywords:    []string{"multi_"},
		Patterns: []Pattern{
			{Name: "key", Regex: regexp.MustCompile(`multi_key_[a-z]{3}`)},
			{Name: "id", Regex: regexp.MustCompile(`multi_id_[a-z]{3}`)},
		},
		Raw:    "{key}",
		RawV2:  "{key}{id}",
		Verify: None{},
	}
	detector := New(r, nil)

	// Two keys, one id: expect a 2x1 cross product, each de-duplicated.
	data := "multi_key_abc multi_key_abc multi_key_def multi_id_xyz"
	results, err := detector.FromData(context.Background(), false, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (2 keys x 1 id)", len(results))
	}
	for _, result := range results {
		if result.SecretParts["id"] != "multi_id_xyz" {
			t.Errorf("SecretParts[id] = %q, want multi_id_xyz", result.SecretParts["id"])
		}
	}
}

func TestFromDataNoMatchReturnsNothing(t *testing.T) {
	detector := New(testRule(), nil)
	results, err := detector.FromData(context.Background(), false, []byte("nothing interesting here"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestNoneVerifierNeverVerifies(t *testing.T) {
	r := testRule()
	r.Verify = None{}
	results, err := New(r, nil).FromData(context.Background(), true, []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Verified || results[0].VerificationError() != nil {
		t.Errorf("None must report not-verified with no error, got verified=%v err=%v",
			results[0].Verified, results[0].VerificationError())
	}
}
