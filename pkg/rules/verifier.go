// This file holds the ways a captured credential can be checked with the
// provider it belongs to: the answer a check can give, the interface every
// check implements, and the three implementations a rule can choose from.

package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

// Outcome is the result of attempting to verify a credential.
//
// Three values rather than a bool, because "we asked the provider and it said
// no" and "we never got an answer" are different facts that lead to different
// decisions. Collapsing them would either hide live credentials behind a
// network blip or flood a scan with findings that were actually disproven.
type Outcome uint8

const (
	// Unknown means verification was inconclusive: a transport error, a
	// timeout, or a response the rule does not account for. Reported as
	// unverified with a verification error attached, so the reason survives
	// into the output.
	Unknown Outcome = iota
	// Valid means the credential works.
	Valid
	// Invalid means the provider rejected the credential. Reported as
	// unverified with no error, because the answer was definitive.
	Invalid
)

// Verifier decides whether a set of captured credentials is valid.
//
// It returns the outcome, any extra details worth reporting alongside the
// finding, and an error explaining an Unknown outcome. The error is only
// meaningful for Unknown: Valid and Invalid are both answers, not failures.
type Verifier interface {
	Verify(ctx context.Context, captures Captures, client *http.Client) (Outcome, map[string]string, error)
}

// None performs no verification. Results are reported as unverified with no
// error, matching how a detector with no verification step behaves.
type None struct{}

// Verify always reports the credential as unverified, without contacting
// anything.
func (None) Verify(context.Context, Captures, *http.Client) (Outcome, map[string]string, error) {
	return Invalid, nil, nil
}

// Func adapts a Go function into a Verifier, for providers whose verification
// needs request signing, a database connection, or other logic a declarative
// rule cannot express. It is the escape hatch that keeps the rule format from
// having to grow a new field every time one provider does something unusual.
type Func func(ctx context.Context, captures Captures, client *http.Client) (Outcome, map[string]string, error)

// Verify calls the wrapped function.
func (f Func) Verify(ctx context.Context, captures Captures, client *http.Client) (Outcome, map[string]string, error) {
	return f(ctx, captures, client)
}

// Status is a set of HTTP status codes.
type StatusCodes []int

func (s StatusCodes) contains(code int) bool {
	return slices.Contains(s, code)
}

// Extract pulls a value out of a verification response body into ExtraData,
// so a finding can carry useful context such as the scopes a token grants.
type Extract struct {
	// JSONField is a top-level field name in the JSON response body. An
	// array value is joined into a single string using Join, which defaults
	// to a comma.
	JSONField string
	Join      string
}

// HTTP verifies a credential with a single request whose response status
// decides the outcome, optionally qualified by the response body.
type HTTP struct {
	// Method defaults to GET. URL, the header and query values, the body
	// field values, and the basic auth fields are placeholder templates:
	// "{name}" is replaced with the value captured by the pattern of that
	// name.
	Method    string
	URL       string
	Headers   map[string]string
	Query     map[string]string
	BasicUser string
	BasicPass string

	// Body, when set, is sent as a JSON object. It is a map rather than a
	// string of JSON so that encoding/json does the quoting: a captured value
	// holding a quote or a backslash would otherwise break the body it was
	// pasted into. Writing it as a map also means a rule author never has to
	// think about which brace in their body is a placeholder.
	Body map[string]string

	// Valid and Invalid are disjoint sets of status codes, and a status in
	// neither yields Unknown.
	//
	// Both are listed explicitly, rather than treating "not success" as
	// failure, because which codes mean what is provider-specific. A 403 can
	// mean the key is real but lacks a scope, which proves it is live; at
	// another provider the same code means the key is dead. Requiring a rule
	// to name the codes it understands keeps it from claiming an outcome for
	// a response nobody thought about.
	ValidStatus   StatusCodes
	InvalidStatus StatusCodes

	// ValidBodyContains, when set, further qualifies a status matching
	// Valid: the response body must contain this substring, or the outcome
	// becomes Invalid. Some APIs answer 200 for requests that failed for
	// non-credential reasons, so the status alone is not always enough.
	ValidBodyContains string

	// ValidExtraData is merged into a result's ExtraData on a Valid outcome
	// only. Use it for details that are meaningless unless the credential was
	// confirmed live; details that hold regardless belong on Rule.ExtraData.
	ValidExtraData map[string]string

	// Extract runs only on a Valid outcome.
	Extract map[string]Extract

	// MaxBody caps how much of the response body is read; zero means 4 KiB.
	// The body is only read at all when ValidBodyContains or Extract is set,
	// so most rules never pay for it.
	MaxBody int64
}

const defaultMaxBody = 4 << 10

// Verify builds the request described by h, substituting the captured values,
// sends it, and maps the response to an outcome.
func (h HTTP) Verify(ctx context.Context, captures Captures, client *http.Client) (Outcome, map[string]string, error) {
	req, err := h.buildRequest(ctx, captures)
	if err != nil {
		return Unknown, nil, err
	}

	res, err := clientOrDefault(client).Do(req)
	if err != nil {
		// No answer at all, so nothing has been learned about the credential.
		return Unknown, nil, err
	}
	defer func() {
		// Drain before closing so the connection can be reused rather than
		// torn down and redialled for the next candidate.
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	// Invalid is checked before Valid so an explicit rejection wins if a rule
	// ever lists a code in both. Validate rejects that overlap up front, so
	// this is a safety net rather than the primary guard.
	if h.InvalidStatus.contains(res.StatusCode) {
		return Invalid, nil, nil
	}
	if !h.ValidStatus.contains(res.StatusCode) {
		return Unknown, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	// The status says valid. If nothing needs the body, stop here without
	// reading it.
	if h.ValidBodyContains == "" && len(h.Extract) == 0 {
		return Valid, h.withValidExtraData(nil), nil
	}

	maxBody := h.MaxBody
	if maxBody == 0 {
		maxBody = defaultMaxBody
	}
	// Bounded read: a provider returning a huge body should not cost a scan
	// an unbounded allocation.
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return Unknown, nil, err
	}
	if h.ValidBodyContains != "" && !strings.Contains(string(body), h.ValidBodyContains) {
		return Invalid, nil, nil
	}
	return Valid, h.withValidExtraData(extractJSON(body, h.Extract)), nil
}

// verifyURL builds the address to verify this candidate against.
//
// Ordinarily URL is a full address and renderURL fills values into it,
// refusing one anywhere that would let scanned data redirect the request.
// When captures carries an endpoint - a rule with Rule.Endpoint configured -
// URL means something different: it is a path, and the endpoint is the base
// it gets joined onto, the same way a hand-written detector that supports
// several addresses builds its request with url.JoinPath(baseURL, path).
// That is deliberately not routed through renderURL's placeholder rules: an
// endpoint is meant to choose where the request goes, so treating it as a
// value to fill into a fixed address would be checking it against the wrong
// rule and then failing every such verification.
func (h HTTP) verifyURL(captures Captures) (*url.URL, error) {
	base, ok := captures[endpointCaptureName]
	if !ok {
		return renderURL(h.URL, captures)
	}
	joined, err := url.JoinPath(base, render(h.URL, escapedForPath(captures)))
	if err != nil {
		return nil, err
	}
	return url.Parse(joined)
}

// buildRequest turns the rule's templates into a concrete request, filling in
// the captured values.
//
// Every value substituted here came out of scanned data, which means it is
// attacker-controlled: a repository can contain a "credential" crafted to
// contain newlines or ampersands. Each place a value lands is therefore
// checked or escaped for that context.
func (h HTTP) buildRequest(ctx context.Context, captures Captures) (*http.Request, error) {
	endpoint, err := h.verifyURL(captures)
	if err != nil {
		return nil, err
	}
	if len(h.Query) > 0 {
		// Set through url.Values so a value containing "&" or "=" is escaped
		// into one parameter instead of silently becoming several.
		query := endpoint.Query()
		for name, tmpl := range h.Query {
			query.Set(name, render(tmpl, captures))
		}
		endpoint.RawQuery = query.Encode()
	}

	// Fill in the captured values first, then marshal, so json.Marshal does
	// the escaping on values that came out of scanned data.
	var body io.Reader
	if len(h.Body) > 0 {
		fields := make(map[string]string, len(h.Body))
		for name, tmpl := range h.Body {
			fields[name] = render(tmpl, captures)
		}
		encoded, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}

	method := h.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}

	for name, tmpl := range h.Headers {
		value := render(tmpl, captures)
		// A captured value containing CR or LF would end the header and let
		// the rest be read as more headers, so refuse instead of sending it.
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("captured value is not a valid %s header", name)
		}
		req.Header.Set(name, value)
	}
	if h.BasicUser != "" || h.BasicPass != "" {
		// SetBasicAuth base64-encodes both parts, so no escaping is needed.
		req.SetBasicAuth(render(h.BasicUser, captures), render(h.BasicPass, captures))
	}
	if len(h.Body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// withValidExtraData combines the rule's confirmed-only values with whatever
// was pulled out of the response body. Extracted values win on a key clash,
// since they describe this specific credential rather than the provider in
// general.
func (h HTTP) withValidExtraData(extracted map[string]string) map[string]string {
	if len(h.ValidExtraData) == 0 {
		return extracted
	}
	merged := make(map[string]string, len(h.ValidExtraData)+len(extracted))
	maps.Copy(merged, h.ValidExtraData)
	maps.Copy(merged, extracted)
	return merged
}

// clientOrDefault supplies the standard detector HTTP client when a caller
// passes none. That client carries a response timeout; one without would let a
// provider that accepts a connection and then never answers hold up a scan
// indefinitely.
func clientOrDefault(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return common.SaneHttpClient()
}

// extractJSON reads the named top-level fields out of a JSON response body.
//
// A body that is not JSON, or is missing a field, is not an error: the
// credential has already been confirmed valid by its status code, and failing
// the whole verification because a provider changed a field name would turn a
// true finding into a false negative. Missing values are simply left out.
func extractJSON(body []byte, spec map[string]Extract) map[string]string {
	if len(spec) == 0 {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := make(map[string]string, len(spec))
	for name, extract := range spec {
		value, ok := doc[extract.JSONField]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			out[name] = typed
		case []any:
			// Arrays are flattened to one string, since ExtraData is a
			// map[string]string and a list of scopes reads fine joined.
			items := make([]string, 0, len(typed))
			for _, item := range typed {
				items = append(items, fmt.Sprint(item))
			}
			separator := extract.Join
			if separator == "" {
				separator = ","
			}
			if len(items) > 0 {
				out[name] = strings.Join(items, separator)
			}
		default:
			out[name] = fmt.Sprint(typed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
