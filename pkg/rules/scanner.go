// This file holds the part that runs: turning a Rule into a detector the
// engine can call, finding candidate credentials in a chunk of scanned data,
// and recording what verification said about each one.

package rules

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// maxTotalMatches caps how many candidate credentials one chunk can produce.
//
// A rule combining two loosely constrained patterns multiplies out: fifty
// matches of each would be two and a half thousand candidates, each of which
// would be verified with its own request. The cap keeps one unusual file from
// turning into a flood of traffic at a provider.
const maxTotalMatches = 100

type scanner struct {
	rule Rule

	// patterns is rule.Patterns with every regex compiled, built once by New.
	patterns []compiledPattern

	// endpointPattern is rule.Endpoint.Pattern compiled, or nil when the
	// rule declares none. Unlike patterns, finding nothing from it does not
	// stop the rule from reporting a candidate.
	endpointPattern *compiledPattern

	// endpoints is non-nil exactly when rule.Endpoint.configured(), and
	// drives which addresses a candidate is verified against. It is also
	// embedded into endpointScanner to expose detectors.EndpointCustomizer,
	// so the two always agree on whether this rule supports endpoints.
	endpoints *detectors.EndpointSetter

	client *http.Client
}

// Every rule is handed a chunk span, so MaxCredentialSpan - named by the
// detectors.MultiPartCredentialProvider interface this implements, not by
// this package - is implemented here for all of them. See Rule.chunkSpan.
func (s *scanner) MaxCredentialSpan() int64 { return s.rule.chunkSpan() }

// Version is different: the engine reads it off a detector to tell two
// implementations of the same provider apart, and a rule that declares none is
// not a version zero, it is a provider with only one implementation. A type
// either has the method or it does not, for every rule built from it, so the
// versioned rules get their own type and New picks between the two.
type versionedScanner struct{ *scanner }

func (s versionedScanner) Version() int { return s.rule.Version }

// endpointScanner wraps a scanner to expose detectors.EndpointCustomizer and,
// when the rule has a cloud address, detectors.CloudProvider. Only built when
// rule.Endpoint.configured(), the same way versionedScanner only exists for a
// rule with a Version: a rule that does not ask for the behaviour should not
// advertise the interface, since the engine would otherwise think it can hand
// this rule a user-configured endpoint that nothing ever reads.
type endpointScanner struct {
	*scanner
	*detectors.EndpointSetter
}

var (
	_ detectors.EndpointCustomizer = (*endpointScanner)(nil)
	_ detectors.CloudProvider      = (*endpointScanner)(nil)
)

func (s *endpointScanner) CloudEndpoint() string { return s.rule.Endpoint.Cloud }

// versionedEndpointScanner is for the rule that needs both wrappers. No rule
// does yet, but nothing stops a future one from declaring a Version and an
// Endpoint together, and it costs four lines to not leave that combination
// unsupported.
type versionedEndpointScanner struct{ *endpointScanner }

func (s versionedEndpointScanner) Version() int { return s.rule.Version }

// New builds a detectors.Detector from r. Verification requests use client, or
// the standard detector HTTP client when client is nil. It panics if r is
// invalid; see Validate.
func New(r Rule, client *http.Client) detectors.Detector {
	// Compiled here and handed to the scanner, so the expressions are built
	// once per detector rather than once per chunk. Validate needs them too,
	// which is why it takes them rather than compiling its own.
	compiled, problems := r.compile()
	endpointPattern, err := r.compileEndpoint()
	if err != nil {
		problems = append(problems, fmt.Errorf("%s: %w", r.identity(), err))
	}
	// Every problem already names its own rule (see Rule.identity), so the
	// panic needs no "invalid rule %s" of its own - that would just repeat
	// it in front of every line.
	if err := r.validate(compiled, endpointPattern, problems); err != nil {
		panic(fmt.Sprintf("invalid rule: %v", err))
	}
	// With one pattern there is only one thing SecretID could refer to, so
	// filling it in saves every such rule from repeating itself.
	if r.SecretID == "" && len(r.Patterns) == 1 {
		r.SecretID = "{" + r.Patterns[0].Name + "}"
	}
	base := &scanner{rule: r, patterns: compiled, endpointPattern: endpointPattern, client: client}

	if !r.Endpoint.configured() {
		if r.Version > 0 {
			return versionedScanner{base}
		}
		return base
	}

	// Replace builds this detector after defaults.DefaultDetectors() already
	// ran its own "turn every EndpointCustomizer on" pass over the
	// hand-written detectors being swapped out - a pass this detector did
	// not exist for yet. Without matching it here, swapping in a rule would
	// silently stop verifying against the provider's cloud and against
	// endpoints found in scanned data, even though nothing asked for that.
	base.endpoints = &detectors.EndpointSetter{}
	base.endpoints.SetCloudEndpoint(r.Endpoint.Cloud)
	base.endpoints.UseCloudEndpoint(true)
	base.endpoints.UseFoundEndpoints(true)

	wrapped := &endpointScanner{scanner: base, EndpointSetter: base.endpoints}
	if r.Version > 0 {
		return versionedEndpointScanner{wrapped}
	}
	return wrapped
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
	capturesByPattern := make([][]string, len(s.patterns))
	for i, pattern := range s.patterns {
		found := findUniqueCaptures(pattern, text)
		if len(found) == 0 {
			return nil, nil
		}
		capturesByPattern[i] = found
	}

	// A chunk can hold several IDs and several keys with no way to tell which
	// pairs with which, so every combination is treated as a candidate and the
	// provider decides which are real.
	candidates := crossProduct(s.patterns, capturesByPattern, maxTotalMatches, s.rule.DistinctCaptures)

	// A found endpoint is optional, so it is collected separately from the
	// patterns loop above rather than folded into it: finding none must not
	// discard every candidate the way an empty required pattern does.
	var foundEndpoints []string
	if s.endpointPattern != nil {
		foundEndpoints = findUniqueCaptures(*s.endpointPattern, text)
	}

	results := make([]detectors.Result, 0, len(candidates))
	for _, captures := range candidates {
		for _, endpoint := range s.endpointsFor(foundEndpoints) {
			resultCaptures := captures
			if s.endpoints != nil {
				resultCaptures = withEndpoint(captures, endpoint)
			}
			result := detectors.Result{
				DetectorType: s.rule.Type,
				Raw:          []byte(render(s.rule.SecretID, resultCaptures)),
				SecretParts:  map[string]string(resultCaptures),
			}
			if s.rule.FullSecretID != "" {
				result.RawV2 = []byte(render(s.rule.FullSecretID, resultCaptures))
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
				s.applyVerification(ctx, &result, resultCaptures)
			}
			results = append(results, result)
		}
	}
	return results, nil
}

// endpointsFor returns the addresses this candidate should be verified
// against. A rule with no Endpoint config always answers with exactly one
// entry, an empty string meaning "no endpoint", so the loop around it runs
// once and resultCaptures is left untouched.
//
// A rule that does declare Endpoint can answer with none at all: that is
// what happens when nothing configured a cloud address, found nothing in the
// data, and no caller set a configured endpoint either. There is then
// nowhere to verify this candidate against, so it is dropped rather than
// reported unverified - the same thing the hand-written detectors this
// mirrors do, since their own "for _, endpoint := range s.Endpoints(...)"
// loop likewise runs zero times.
func (s *scanner) endpointsFor(found []string) []string {
	if s.endpoints == nil {
		return []string{""}
	}
	return s.endpoints.Endpoints(found...)
}

// withEndpoint copies captures with the endpoint it was verified against
// added under the reserved name, without mutating the shared candidate.
func withEndpoint(captures Captures, endpoint string) Captures {
	out := make(Captures, len(captures)+1)
	maps.Copy(out, captures)
	out[endpointCaptureName] = endpoint
	return out
}

// applyVerification runs the rule's verifier for one candidate and records the
// answer on the result.
func (s *scanner) applyVerification(ctx context.Context, result *detectors.Result, captures Captures) {
	// Every verifier is handed a usable client, so a Func verifier can call it
	// without checking for nil. New is often given nil, meaning "use the
	// standard detector client".
	outcome, extra, err := s.rule.Verify.Verify(ctx, captures, clientOrDefault(s.client))

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
		result.SetVerificationError(err, capturedValues(captures)...)
	}

	for name, value := range extra {
		if result.ExtraData == nil {
			result.ExtraData = map[string]string{}
		}
		result.ExtraData[name] = value
	}
}

// capturedValues returns every value in captures, for redaction.
func capturedValues(captures Captures) []string {
	return slices.Collect(maps.Values(captures))
}

// findUniqueCaptures runs one pattern over the text and returns each distinct
// value it captured, in the order first seen.
//
// Duplicates are dropped because the same credential written twice in a file is
// one credential, and keeping both would mean verifying it twice and reporting
// it twice.
func findUniqueCaptures(pattern compiledPattern, text string) []string {
	seen := make(map[string]struct{})
	var values []string

	for _, match := range pattern.regex.FindAllStringSubmatch(text, -1) {
		// match[0] is the whole match and match[1:] are the capture groups.
		group := 0
		if pattern.Group != nil {
			group = *pattern.Group
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
		// Too orderly to be a random key. See Pattern.MinEntropy.
		if pattern.MinEntropy > 0 && detectors.StringShannonEntropy(value) < pattern.MinEntropy {
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
//
// When distinct is set, a value is never used twice in the same combination.
// See Rule.DistinctCaptures for when a rule wants that.
func crossProduct(patterns []compiledPattern, capturesByPattern [][]string, limit int, distinct bool) []Captures {
	combinations := []Captures{{}}

	for i, pattern := range patterns {
		next := make([]Captures, 0, len(combinations)*len(capturesByPattern[i]))
		for _, existing := range combinations {
			for _, value := range capturesByPattern[i] {
				if len(next) >= limit {
					return next
				}
				// This value already fills another slot in this combination,
				// so pairing it with itself would invent a credential.
				if distinct && holdsValue(existing, value) {
					continue
				}
				combination := make(Captures, len(existing)+1)
				maps.Copy(combination, existing)
				combination[pattern.Name] = value
				next = append(next, combination)
			}
		}
		combinations = next
	}
	return combinations
}

// holdsValue reports whether any slot in captures already holds value.
func holdsValue(captures Captures, value string) bool {
	for _, held := range captures {
		if held == value {
			return true
		}
	}
	return false
}
