// Tests for checking a captured credential with the provider it belongs to:
// what each answer means, and how the request is built.

package rules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// Scanned data reaches outbound verification requests, so a captured value must
// not be able to forge a header or smuggle a query parameter.
func TestInjectionIsRejected(t *testing.T) {
	h := HTTP{
		URL:         "https://example.invalid/",
		Headers:     map[string]string{"X-Key": "{key}"},
		ValidStatus: StatusCodes{200},
	}
	_, _, err := h.Verify(context.Background(),
		Captures{"key": "abc\r\nX-Admin: true"}, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "not a valid X-Key header") {
		t.Errorf("CRLF in a capture must be rejected, got %v", err)
	}

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	q := HTTP{URL: srv.URL, Query: map[string]string{"q": "{key}"}, ValidStatus: StatusCodes{200}}
	if _, _, err := q.Verify(context.Background(), Captures{"key": "a&admin=1"}, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "a&admin=1" {
		t.Errorf("query value was not escaped as one parameter: %q", gotQuery)
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

// TestFuncVerifierGetsAClient covers New being given nil, which is what the
// command line does. A verifier must never be handed a nil client to call.
func TestFuncVerifierGetsAClient(t *testing.T) {
	var handed *http.Client
	rule := testRule()
	rule.Verify = Func(func(_ context.Context, _ Captures, client *http.Client) (Outcome, map[string]string, error) {
		handed = client
		return Invalid, nil, nil
	})

	detector := New(rule, nil)
	if _, err := detector.FromData(context.Background(), true, []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	if handed == nil {
		t.Fatal("verifier was handed a nil client")
	}
}

// A captured value goes into the body as scanned data, quotes and all. Because
// Body is a map rather than a string of JSON, encoding/json quotes it, so a
// value carrying a quote cannot break out of its field.
func TestJSONBodyEscapesCapturedValues(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	nasty := `a","admin":true,"x":"b`
	verifier := HTTP{
		Method:      http.MethodPost,
		URL:         srv.URL,
		Body:        map[string]string{"key": "{key}"},
		ValidStatus: StatusCodes{200},
	}
	if _, _, err := verifier.Verify(context.Background(), Captures{"key": nasty}, srv.Client()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The body must still be one field holding the whole value.
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v (%s)", err, got)
	}
	if len(decoded) != 1 || decoded["key"] != nasty {
		t.Errorf("captured value escaped its field: %s", got)
	}
}
