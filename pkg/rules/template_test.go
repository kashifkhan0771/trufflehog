// Tests for filling "{name}" placeholders into text and URLs.

package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRenderIgnoresBracesThatAreNotNames covers sending JSON: a request body is
// full of braces that are part of the text, and only "{name}" should be
// swapped for a captured value.
func TestRenderIgnoresBracesThatAreNotNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		tmpl string
		want string
	}{
		{"plain json", `{"service": "list"}`, `{"service": "list"}`},
		{"nested json", `{"query":"{ sshList {id, name}}"}`, `{"query":"{ sshList {id, name}}"}`},
		{"value inside json", `{"key":"{key}"}`, `{"key":"` + testSecret + `"}`},
		{"value on its own", `{key}`, testSecret},
		{"unknown name still substitutes", `{nope}`, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := render(tc.tmpl, Captures{"key": testSecret}); got != tc.want {
				t.Errorf("render(%q) = %q, want %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

func TestNonHTTPSchemeRejected(t *testing.T) {
	h := HTTP{URL: "file:///etc/passwd", ValidStatus: StatusCodes{200}}
	if _, _, err := h.Verify(context.Background(), Captures{}, http.DefaultClient); err == nil {
		t.Error("non-http scheme must be rejected")
	}
}

// TestURLPathValuesAreEscaped covers a value landing in the URL path. The
// pattern here allows characters that would otherwise reshape the address, so
// the request must still go to the path the rule described.
func TestURLPathValuesAreEscaped(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The path as it arrived on the wire, before the server decodes it.
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rule := testRule()
	rule.Patterns = []Pattern{
		{Name: "key", Regex: `tk_[a-z0-9/?#]+`},
	}
	rule.Verify = HTTP{
		URL:           srv.URL + "/accounts/{key}/flows",
		ValidStatus:   StatusCodes{200},
		InvalidStatus: StatusCodes{401},
	}

	detector := New(rule, srv.Client())
	_, err := detector.FromData(context.Background(), true, []byte("tk_abc/../admin?x=1"))
	if err != nil {
		t.Fatal(err)
	}
	// The value matched here is "tk_abc/", and its slash must arrive escaped
	// rather than as an extra path segment.
	if want := "/accounts/tk_abc%2F/flows"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
}
