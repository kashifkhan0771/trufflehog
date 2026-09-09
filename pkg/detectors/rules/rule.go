// Package rules implements detectors that are declared as data rather than
// written as bespoke Go packages.
//
// A Rule describes one detector: the keywords that gate it, one or more named
// regex patterns, and how a match is verified. New turns a Rule into a
// detectors.Detector, so a rule-backed detector behaves identically to a
// hand-written one from the engine's point of view.
//
// Three verification shapes are supported: a single HTTP request whose
// response decides the outcome (HTTP), no verification at all (None), and an
// arbitrary Go function for providers whose verification cannot be expressed
// declaratively (Func).
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/net/http/httpguts"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// Creds holds the values a rule captured from one candidate credential, keyed
// by the pattern name that captured each one.
//
// For a single-pattern rule this holds one entry, such as {"key": "SG.abc..."}.
// For a rule matching an ID and a secret separately it holds both, such as
// {"id": "y3ejw028", "key": "cr479du..."}. The same map is what placeholder
// templates read from and what a Verifier is handed, so a rule author refers to
// a captured value by the pattern name they chose for it.
type Creds map[string]string

// Pattern is one named regex a rule looks for.
//
// Capture selects which parenthesised group of the regex holds the secret. When
// it is nil the rule falls back to group 1 if the regex defines one, and group 0
// (the entire match) otherwise. That default exists because the two common ways
// of writing a detector regex are "match exactly the token" (no group) and
// "match some surrounding context, and capture the token inside it" (one group),
// and picking the right one automatically keeps most rules from having to say.
type Pattern struct {
	Name    string
	Regex   *regexp.Regexp
	Capture *int
}

// Rule is a detector expressed as data. Every field is a value except Verify,
// which is an interface so a provider needing real verification logic can
// supply it.
type Rule struct {
	Type        detector_typepb.DetectorType
	Version     int
	Description string
	Keywords    []string

	// Patterns are the named regexes that make up a credential. Every one of
	// them must match for a rule to report anything, since a rule listing an
	// ID and a key is describing one credential made of both halves.
	//
	// Order them most selective first. Matching stops at the first pattern
	// that finds nothing, so the cheapest way to reject a chunk is to look
	// for the distinctive part before the vague one. Putting a loose pattern
	// first, such as a bare run of alphanumerics, means it runs against every
	// chunk the keywords let through and the early exit almost never fires.
	//
	// This only affects speed, never results: the outcome is the same
	// whatever the order, because all patterns are required anyway. It
	// matters because most chunks that get this far contain no credential, so
	// rejecting them quickly is the common path rather than the rare one.
	Patterns []Pattern

	// Raw and RawV2 are placeholder templates, such as "{key}" or
	// "{key}{id}", and together they form a finding's identity.
	//
	// Treat them as a stored contract, not a formatting choice. They are
	// hashed into the identifier a finding is recorded under, so changing
	// either one for an existing detector does not merely alter this scan: it
	// makes every record already stored under the old value unreachable.
	//
	// A rule replacing a hand-written detector must therefore reproduce that
	// detector's Raw and RawV2 exactly, including leaving RawV2 empty when the
	// original leaves it empty, whatever the merits of the original choice.
	//
	// For a genuinely new rule the choice is about how findings are reported:
	//
	//   - Set RawV2 (for example "{key}{id}") to report every combination of
	//     captures separately. Use this when each combination is a distinct
	//     credential deserving its own finding.
	//
	//   - Leave RawV2 empty to collapse every combination sharing a Raw into
	//     one finding. Use this when the other patterns are supporting halves
	//     of one credential, and where a loose pattern would otherwise pair
	//     one real key with every lookalike string nearby and report the same
	//     exposed key many times over.
	//
	// Raw defaults to the sole pattern when a rule has exactly one, since
	// there is nothing else it could be.
	Raw   string
	RawV2 string

	ExtraData map[string]string
	Verify    Verifier

	// MaxCredentialSpan widens the window of chunk data the engine passes to
	// FromData, in bytes. Leave it zero unless a rule needs it.
	//
	// The engine normally hands a detector a small window around the keyword
	// it matched. That is fine for a single token, but a rule matching an ID
	// and a key separately will miss one of them if they sit on different
	// lines far enough apart, because only part of the credential lands
	// inside the window. Setting this widens the window so both halves arrive
	// in the same call.
	MaxCredentialSpan int64
}

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
	Verify(ctx context.Context, creds Creds, client *http.Client) (Outcome, map[string]string, error)
}

// None performs no verification. Results are reported as unverified with no
// error, matching how a detector with no verification step behaves.
type None struct{}

// Verify always reports the credential as unverified, without contacting
// anything.
func (None) Verify(context.Context, Creds, *http.Client) (Outcome, map[string]string, error) {
	return Invalid, nil, nil
}

// Func adapts a Go function into a Verifier, for providers whose verification
// needs request signing, a database connection, or other logic a declarative
// rule cannot express. It is the escape hatch that keeps the rule format from
// having to grow a new field every time one provider does something unusual.
type Func func(ctx context.Context, creds Creds, client *http.Client) (Outcome, map[string]string, error)

// Verify calls the wrapped function.
func (f Func) Verify(ctx context.Context, creds Creds, client *http.Client) (Outcome, map[string]string, error) {
	return f(ctx, creds, client)
}

// Status is a set of HTTP status codes.
type Status []int

func (s Status) contains(code int) bool {
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
	// Method defaults to GET. URL, the header and query values, Body, and
	// the basic auth fields are placeholder templates: "{name}" is replaced
	// with the value captured by the pattern of that name.
	Method    string
	URL       string
	Headers   map[string]string
	Query     map[string]string
	Body      string
	BasicUser string
	BasicPass string

	// Valid and Invalid are disjoint sets of status codes, and a status in
	// neither yields Unknown.
	//
	// Both are listed explicitly, rather than treating "not success" as
	// failure, because which codes mean what is provider-specific. A 403 can
	// mean the key is real but lacks a scope, which proves it is live; at
	// another provider the same code means the key is dead. Requiring a rule
	// to name the codes it understands keeps it from claiming an outcome for
	// a response nobody thought about.
	Valid   Status
	Invalid Status

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
func (h HTTP) Verify(ctx context.Context, creds Creds, client *http.Client) (Outcome, map[string]string, error) {
	req, err := h.buildRequest(ctx, creds)
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
	if h.Invalid.contains(res.StatusCode) {
		return Invalid, nil, nil
	}
	if !h.Valid.contains(res.StatusCode) {
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

// buildRequest turns the rule's templates into a concrete request, filling in
// the captured values.
//
// Every value substituted here came out of scanned data, which means it is
// attacker-controlled: a repository can contain a "credential" crafted to
// contain newlines or ampersands. Each place a value lands is therefore
// checked or escaped for that context.
func (h HTTP) buildRequest(ctx context.Context, creds Creds) (*http.Request, error) {
	endpoint, err := renderURL(h.URL, creds)
	if err != nil {
		return nil, err
	}
	if len(h.Query) > 0 {
		// Set through url.Values so a value containing "&" or "=" is escaped
		// into one parameter instead of silently becoming several.
		query := endpoint.Query()
		for name, tmpl := range h.Query {
			query.Set(name, render(tmpl, creds))
		}
		endpoint.RawQuery = query.Encode()
	}

	var body io.Reader
	if h.Body != "" {
		body = strings.NewReader(render(h.Body, creds))
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
		value := render(tmpl, creds)
		// A captured value containing CR or LF would end the header and let
		// the rest be read as more headers, so refuse instead of sending it.
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("captured value is not a valid %s header", name)
		}
		req.Header.Set(name, value)
	}
	if h.BasicUser != "" || h.BasicPass != "" {
		// SetBasicAuth base64-encodes both parts, so no escaping is needed.
		req.SetBasicAuth(render(h.BasicUser, creds), render(h.BasicPass, creds))
	}
	if h.Body != "" && req.Header.Get("Content-Type") == "" {
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

// render replaces every "{name}" in tmpl with the value captured by the pattern
// called name.
//
// It walks the template once, copying the text between placeholders straight
// through and looking up whatever sits inside each pair of braces. A name with
// no matching capture renders as empty, and an unclosed brace is copied
// through as ordinary text rather than treated as an error, because Validate
// has already rejected both cases at construction time.
//
// This is deliberately not text/template. A rule has nothing to branch on or
// loop over, so the extra machinery would buy nothing while adding a function
// map to audit and missing-key behaviour to get wrong.
func render(tmpl string, creds Creds) string {
	// Overwhelmingly common case: a constant with no placeholders at all.
	if !strings.ContainsRune(tmpl, '{') {
		return tmpl
	}
	var out strings.Builder
	out.Grow(len(tmpl))
	for {
		openIdx := strings.IndexByte(tmpl, '{')
		if openIdx < 0 {
			out.WriteString(tmpl)
			return out.String()
		}
		// Searched from the opening brace, so this offset is relative to it,
		// not to the start of the remaining template.
		closeIdx := strings.IndexByte(tmpl[openIdx:], '}')
		if closeIdx < 0 {
			out.WriteString(tmpl)
			return out.String()
		}
		out.WriteString(tmpl[:openIdx])
		out.WriteString(creds[tmpl[openIdx+1:openIdx+closeIdx]])
		tmpl = tmpl[openIdx+closeIdx+1:]
	}
}

// placeholders returns every name referenced by "{...}" in tmpl. Validate uses
// it to catch a rule that refers to a pattern it never declared, which would
// otherwise show up as an empty value in a request at scan time.
func placeholders(tmpl string) []string {
	var names []string
	for {
		openIdx := strings.IndexByte(tmpl, '{')
		if openIdx < 0 {
			return names
		}
		closeIdx := strings.IndexByte(tmpl[openIdx:], '}')
		if closeIdx < 0 {
			return names
		}
		names = append(names, tmpl[openIdx+1:openIdx+closeIdx])
		tmpl = tmpl[openIdx+closeIdx+1:]
	}
}

// renderURL substitutes captured values into a URL template and rejects any
// scheme other than HTTP. Without that check a captured value landing at the
// start of the template could redirect verification at something like a local
// file path.
func renderURL(tmpl string, creds Creds) (*url.URL, error) {
	endpoint, err := url.Parse(render(tmpl, creds))
	if err != nil {
		return nil, err
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, fmt.Errorf("verification URL scheme %q is not http(s)", endpoint.Scheme)
	}
	return endpoint, nil
}

// Validate reports everything wrong with a rule at once, joined into a single
// error, so a rule author sees every problem in one run instead of fixing them
// one at a time.
//
// New calls it and panics on failure. A Rule is a package-level value built at
// startup, so an invalid one is a mistake in the source rather than something
// that can happen part way through a scan, and failing immediately is better
// than scanning with a detector that quietly does the wrong thing.
func (r Rule) Validate() error {
	var problems []error
	addProblem := func(format string, args ...any) {
		problems = append(problems, fmt.Errorf(format, args...))
	}

	if len(r.Keywords) == 0 {
		addProblem("no keywords")
	}
	for _, keyword := range r.Keywords {
		// Keywords feed the engine's pre-filter, which decides which chunks
		// are worth running this rule against. A single character matches
		// almost everything, so the rule would run on every chunk in the scan
		// and the pre-filter would stop doing its job.
		if len(keyword) < 2 {
			addProblem("keyword %q is shorter than 2 characters", keyword)
		}
	}

	if len(r.Patterns) == 0 {
		addProblem("no patterns")
	}
	patternNames := make(map[string]bool, len(r.Patterns))
	for _, pattern := range r.Patterns {
		if pattern.Name == "" || pattern.Regex == nil {
			addProblem("pattern with empty name or nil regex")
			continue
		}
		// Names address captures, so a duplicate would mean one pattern's
		// value silently overwrote another's.
		if patternNames[pattern.Name] {
			addProblem("duplicate pattern name %q", pattern.Name)
		}
		patternNames[pattern.Name] = true
	}

	// Raw cannot be guessed once there is more than one pattern, since which
	// capture identifies the credential is a decision only the rule author can
	// make. RawV2 is deliberately not required here: leaving it empty is a
	// valid choice that collapses combinations into one finding.
	if len(r.Patterns) > 1 && r.Raw == "" {
		addProblem("multi-pattern rule has no Raw")
	}
	if r.Description == "" {
		addProblem("no description")
	}
	if r.Verify == nil {
		addProblem("no verifier (use None{} for detection-only rules)")
	}

	// Every template may only refer to patterns this rule actually declares.
	checkTemplate := func(field, tmpl string) {
		for _, name := range placeholders(tmpl) {
			if !patternNames[name] {
				addProblem("%s references unknown pattern {%s}", field, name)
			}
		}
	}
	checkTemplate("Raw", r.Raw)
	checkTemplate("RawV2", r.RawV2)

	if httpVerifier, ok := r.Verify.(HTTP); ok {
		checkTemplate("URL", httpVerifier.URL)
		checkTemplate("Body", httpVerifier.Body)
		for name, tmpl := range httpVerifier.Headers {
			checkTemplate("header "+name, tmpl)
		}
		for name, tmpl := range httpVerifier.Query {
			checkTemplate("query "+name, tmpl)
		}
		checkTemplate("BasicUser", httpVerifier.BasicUser)
		checkTemplate("BasicPass", httpVerifier.BasicPass)

		// A code in both sets has no defined meaning, and whichever check ran
		// first would decide the outcome.
		for _, code := range httpVerifier.Valid {
			if httpVerifier.Invalid.contains(code) {
				addProblem("status %d is listed as both Valid and Invalid", code)
			}
		}
	}
	return errors.Join(problems...)
}

// maxTotalMatches caps how many candidate credentials one chunk can produce.
//
// A rule combining two loosely constrained patterns multiplies out: fifty
// matches of each would be two and a half thousand candidates, each of which
// would be verified with its own request. The cap keeps one unusual file from
// turning into a flood of traffic at a provider.
const maxTotalMatches = 100

type scanner struct {
	rule   Rule
	client *http.Client
}

// The engine asks a detector what it supports by testing whether it implements
// certain optional interfaces. That means behaviour cannot be switched on per
// rule inside a single type: a type either has the method or it does not, for
// every rule built from it. Implementing MaxCredentialSpan unconditionally
// would widen the scan window for every rule, including the ones that never
// asked and would then be handed more data to search than they need.
//
// So there is one small type per combination, and New picks the one matching
// what a rule actually declares.
type spanScanner struct{ *scanner }

func (s spanScanner) MaxCredentialSpan() int64 { return s.rule.MaxCredentialSpan }

type versionedScanner struct{ *scanner }

func (s versionedScanner) Version() int { return s.rule.Version }

type versionedSpanScanner struct{ *scanner }

func (s versionedSpanScanner) Version() int             { return s.rule.Version }
func (s versionedSpanScanner) MaxCredentialSpan() int64 { return s.rule.MaxCredentialSpan }

// New builds a detectors.Detector from r. Verification requests use client, or
// the standard detector HTTP client when client is nil. It panics if r is
// invalid; see Validate.
func New(r Rule, client *http.Client) detectors.Detector {
	if err := r.Validate(); err != nil {
		panic(fmt.Sprintf("invalid rule %s: %v", r.Type, err))
	}
	// With one pattern there is only one thing Raw could refer to, so filling
	// it in saves every such rule from repeating itself.
	if r.Raw == "" && len(r.Patterns) == 1 {
		r.Raw = "{" + r.Patterns[0].Name + "}"
	}
	base := &scanner{rule: r, client: client}

	switch {
	case r.Version > 0 && r.MaxCredentialSpan > 0:
		return versionedSpanScanner{base}
	case r.Version > 0:
		return versionedScanner{base}
	case r.MaxCredentialSpan > 0:
		return spanScanner{base}
	default:
		return base
	}
}

func (s *scanner) Keywords() []string                 { return s.rule.Keywords }
func (s *scanner) Type() detector_typepb.DetectorType { return s.rule.Type }
func (s *scanner) Description() string                { return s.rule.Description }

// FromData finds candidate credentials in a chunk of scanned data and, when
// asked, verifies each one.
//
// The engine calls this concurrently from several goroutines, so nothing here
// writes to the rule or the scanner; every value it builds is local to the call.
func (s *scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	text := string(data)

	// Collect what each pattern found. Every pattern has to match something:
	// a rule describing an ID and a key is describing one credential made of
	// both halves, so finding only one half means the credential is not here.
	//
	// Bailing on the first empty pattern is what makes a chunk holding no
	// credential cheap, and it is why Rule.Patterns asks for the most
	// selective pattern first.
	capturesByPattern := make([][]string, len(s.rule.Patterns))
	for i, pattern := range s.rule.Patterns {
		found := findUniqueCaptures(pattern, text)
		if len(found) == 0 {
			return nil, nil
		}
		capturesByPattern[i] = found
	}

	// A chunk can hold several IDs and several keys with no way to tell which
	// pairs with which, so every combination is treated as a candidate and the
	// provider decides which are real.
	candidates := crossProduct(s.rule.Patterns, capturesByPattern, maxTotalMatches)

	results := make([]detectors.Result, 0, len(candidates))
	for _, creds := range candidates {
		result := detectors.Result{
			DetectorType: s.rule.Type,
			Raw:          []byte(render(s.rule.Raw, creds)),
			SecretParts:  map[string]string(creds),
		}
		if s.rule.RawV2 != "" {
			result.RawV2 = []byte(render(s.rule.RawV2, creds))
		}
		// A nil ExtraData on the rule leaves it nil on the result, while an
		// empty map leaves an empty map. The two are not interchangeable:
		// they serialise as null and {} respectively.
		if s.rule.ExtraData != nil {
			// Copied rather than shared, because the verifier may add to this
			// map and the rule's own map is reused across every result.
			result.ExtraData = make(map[string]string, len(s.rule.ExtraData))
			maps.Copy(result.ExtraData, s.rule.ExtraData)
		}
		if verify {
			s.applyVerification(ctx, &result, creds)
		}
		results = append(results, result)
	}
	return results, nil
}

// applyVerification runs the rule's verifier for one candidate and records the
// answer on the result.
func (s *scanner) applyVerification(ctx context.Context, result *detectors.Result, creds Creds) {
	outcome, extra, err := s.rule.Verify.Verify(ctx, creds, s.client)

	switch outcome {
	case Valid:
		result.Verified = true
	case Invalid:
		// Left unverified with no error attached. The absence of an error is
		// what marks this as a definitive answer rather than a failed attempt.
	default:
		// Unknown. An error must be attached, since that is the only thing
		// separating this from Invalid downstream. A verifier that returns
		// Unknown without one still gets something usable.
		if err == nil {
			err = errors.New("verification was inconclusive")
		}
		// The captured values are passed so they can be redacted out of the
		// message: verification errors can quote the request that failed.
		result.SetVerificationError(err, capturedValues(creds)...)
	}

	for name, value := range extra {
		if result.ExtraData == nil {
			result.ExtraData = map[string]string{}
		}
		result.ExtraData[name] = value
	}
}

// capturedValues returns every value in creds, for redaction.
func capturedValues(creds Creds) []string {
	return slices.Collect(maps.Values(creds))
}

// findUniqueCaptures runs one pattern over the text and returns each distinct
// value it captured, in the order first seen.
//
// Duplicates are dropped because the same credential written twice in a file is
// one credential, and keeping both would mean verifying it twice and reporting
// it twice.
func findUniqueCaptures(pattern Pattern, text string) []string {
	seen := make(map[string]struct{})
	var values []string

	for _, match := range pattern.Regex.FindAllStringSubmatch(text, -1) {
		// match[0] is the whole match and match[1:] are the capture groups.
		group := 0
		if pattern.Capture != nil {
			group = *pattern.Capture
		} else if len(match) > 1 {
			group = 1
		}
		if group >= len(match) {
			continue
		}
		value := strings.TrimSpace(match[group])
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

// crossProduct builds every combination of one captured value per pattern.
//
// It grows the set one pattern at a time: starting from a single empty
// combination, each pattern replaces the set with a copy of itself for every
// value that pattern found. With two IDs and three keys that is one, then two,
// then six combinations.
//
// It stops as soon as limit combinations exist. Cutting off mid-way is
// deliberate: the alternative is either building the full set first, which is
// the cost being avoided, or dropping the chunk entirely, which would miss real
// credentials sitting alongside noise.
func crossProduct(patterns []Pattern, capturesByPattern [][]string, limit int) []Creds {
	combinations := []Creds{{}}

	for i, pattern := range patterns {
		next := make([]Creds, 0, len(combinations)*len(capturesByPattern[i]))
		for _, existing := range combinations {
			for _, value := range capturesByPattern[i] {
				if len(next) >= limit {
					return next
				}
				combination := make(Creds, len(existing)+1)
				maps.Copy(combination, existing)
				combination[pattern.Name] = value
				next = append(next, combination)
			}
		}
		combinations = next
	}
	return combinations
}
