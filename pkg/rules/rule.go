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
//
// The package is split by job:
//
//	rule.go      what a rule is
//	validate.go  what makes a rule valid
//	verifier.go  the ways a captured credential can be checked
//	template.go  filling "{name}" placeholders into text and URLs
//	scanner.go   running a rule against a chunk of scanned data
//	test.go      the data a rule's tests run from, and SampleText
package rules

import (
	"fmt"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// Captures holds the values a rule pulled out of one candidate credential,
// keyed by the pattern name that captured each one.
//
// For a single-pattern rule this holds one entry, such as {"key": "SG.abc..."}.
// For a rule matching an ID and a secret separately it holds both, such as
// {"id": "y3ejw028", "key": "cr479du..."}. The same map is what placeholder
// templates read from and what a Verifier is handed, so a rule author refers to
// a captured value by the pattern name they chose for it.
type Captures map[string]string

// Pattern is one named regex a rule looks for.
//
// Regex is the source text, not a compiled expression: a rule is data, and New
// compiles it. A rule that cannot compile is rejected by Validate, which New
// runs before building anything, so a broken pattern still cannot reach a scan.
//
// Group selects which parenthesised group of the regex holds the secret. When
// it is nil the rule falls back to group 1 if the regex defines one, and group 0
// (the entire match) otherwise. That default exists because the two common ways
// of writing a detector regex are "match exactly the token" (no group) and
// "match some surrounding context, and capture the token inside it" (one group),
// and picking the right one automatically keeps most rules from having to say.
type Pattern struct {
	Name  string
	Regex string

	// Prefix requires one of these words to appear shortly before the value.
	// It is how a pattern for a plain run of characters avoids matching every
	// hash and filename of the right length: the word has to be there too.
	//
	// Leave it nil for a pattern that identifies itself, such as one matching a
	// token with a fixed prefix of its own. See detectors.PrefixRegex for how
	// close the word has to be.
	//
	// It is a list rather than a flag reading Rule.Keywords because the two are
	// not the same question. Keywords decides which chunks are worth opening,
	// and that net is sometimes deliberately wider than what must sit beside
	// the value. Every word here does have to appear in Keywords, though: a
	// chunk without one never reaches the pattern, so such a word would be
	// asking for something that can never happen.
	Prefix []string

	Group *int

	// MinEntropy drops a captured value whose Shannon entropy falls below
	// this. Zero, the default, means no check.
	//
	// It is for patterns loose enough to match ordinary text: a bare run of
	// alphanumerics of the right length matches a hash, a filename or a line
	// of base64 just as happily as a key. Real keys are random, so they score
	// high; prose and repeated characters score low.
	//
	// It sits on the pattern rather than the rule because the halves of one
	// credential are not equally random. AWS wants a different floor for an
	// access key ID than for its secret.
	MinEntropy float64
}

// compiledPattern is a Pattern with its regex built, including the keyword
// prefix. Nothing outside this package sees one: a rule is written and read as
// data, and this is what the scanner actually runs.
type compiledPattern struct {
	Pattern
	regex *regexp.Regexp
}

// compile builds every pattern's regex, returning whatever went wrong rather
// than stopping at the first failure, so a rule author sees all of it at once.
//
// A pattern that fails to compile still takes its place in the returned slice,
// with a nil regex, so the checks in Validate that do not need one still run
// and report against the right pattern.
func (r Rule) compile() ([]compiledPattern, []error) {
	var problems []error
	compiled := make([]compiledPattern, 0, len(r.Patterns))
	for _, pattern := range r.Patterns {
		built, err := compilePattern(pattern)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", r.identity(), err))
		}
		compiled = append(compiled, built)
	}
	return compiled, problems
}

// identity names this rule in an error message: its detector type, plus the
// version when one is set.
//
// Two rules can share a type and differ only by version - GoDaddyOTE and
// GoDaddyProd both report detector_typepb.DetectorType_GoDaddy - so the type
// alone would not tell a reader which of them a problem belongs to. Every
// problem a rule reports is run through this, so two rules failing in the
// same batch are never mixed up, however the problems end up printed or
// joined together.
func (r Rule) identity() string {
	if r.Version > 0 {
		return fmt.Sprintf("%s/%d", r.Type, r.Version)
	}
	return r.Type.String()
}

// compilePattern builds one pattern's regex, including its keyword prefix.
// The returned compiledPattern is always usable for the checks in Validate
// that do not need a working regex, even when err is set and its own regex
// is nil.
func compilePattern(pattern Pattern) (compiledPattern, error) {
	built := compiledPattern{Pattern: pattern}
	if pattern.Regex == "" {
		return built, nil
	}
	expression := pattern.Regex
	if len(pattern.Prefix) > 0 {
		expression = detectors.PrefixRegex(pattern.Prefix) + expression
	}
	regex, err := regexp.Compile(expression)
	if err != nil {
		return built, fmt.Errorf("pattern %q does not compile: %v", pattern.Name, err)
	}
	built.regex = regex
	return built, nil
}

// compileEndpoint builds Endpoint.Pattern, the same way as a normal pattern,
// under the reserved name "endpoint". Returns nil if the rule declares no
// such pattern.
func (r Rule) compileEndpoint() (*compiledPattern, error) {
	if r.Endpoint.Pattern == nil {
		return nil, nil
	}
	pattern := *r.Endpoint.Pattern
	pattern.Name = endpointCaptureName
	built, err := compilePattern(pattern)
	return &built, err
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

	// SecretID and FullSecretID are placeholder templates, such as "{key}" or
	// "{key}{id}". They identify a finding.
	//
	// SecretID identifies the secret on its own. FullSecretID adds the other
	// captured parts, for rules where the secret alone does not tell two
	// findings apart. They are reported as a result's Raw and RawV2.
	//
	// Treat them as a stored contract, not a formatting choice. Both are
	// hashed into the identifier a finding is recorded under, so changing
	// either one for an existing detector does not merely alter this scan: it
	// makes every record already stored under the old value unreachable.
	//
	// A rule replacing a hand-written detector must therefore reproduce that
	// detector's Raw and RawV2 exactly, including leaving FullSecretID empty
	// when the original leaves RawV2 empty, whatever the merits of the
	// original choice.
	//
	// For a genuinely new rule the choice is about how findings are reported:
	//
	//   - Set FullSecretID (for example "{key}{id}") to report every
	//     combination of captures separately. Use this when each combination is
	//     a distinct credential deserving its own finding.
	//
	//   - Leave FullSecretID empty to collapse every combination sharing a
	//     SecretID into one finding. Use this when the other patterns are
	//     supporting halves of one credential, and where a loose pattern would
	//     otherwise pair one real key with every lookalike string nearby and
	//     report the same exposed key many times over.
	//
	// SecretID defaults to the sole pattern when a rule has exactly one, since
	// there is nothing else it could be.
	SecretID     string
	FullSecretID string

	ExtraData map[string]string
	Verify    Verifier

	// Disabled takes this detector out of the scan completely.
	//
	// Read that literally: Replace removes it from the detector list rather
	// than falling back to the hand-written implementation, so nothing looks
	// for this provider at all. It is a switch for taking a provider out of
	// service, not for choosing between two implementations of it.
	//
	// The zero value is false, so a rule is on unless it says otherwise. A
	// disabled rule is still validated and still needs its test cases, so
	// turning it back on cannot surprise anyone.
	Disabled bool

	// DistinctCaptures drops any candidate where two patterns captured the
	// same string.
	//
	// Set it when two halves of a credential are found by the same regex, or
	// by two regexes loose enough to match each other's values. Without it a
	// single string in the data is paired with itself and reported as a whole
	// credential, which it is not.
	//
	// Leave it off otherwise. A provider can legitimately issue an ID and a
	// key that happen to be identical, and this would throw that away.
	DistinctCaptures bool

	// Test holds the examples this rule's tests are generated from. See Test.
	Test Test

	// MaxChunkSpan overrides how much of the chunk the engine hands this
	// rule, in bytes, measured either side of the keyword that matched.
	//
	// Leave it zero. Every rule gets a span without asking: defaultChunkSpan
	// for one pattern, multiPatternChunkSpan for more than one - the same
	// numbers a hand-written detector gets by default, or by embedding
	// DefaultMultiPartCredentialProvider. Set this only for a rule those two
	// do not fit, such as one whose hand-written detector asked the engine
	// for something wider still.
	MaxChunkSpan int64

	// Endpoint lets a rule verify a credential against more than one
	// address: a cloud default, an address found in the scanned data, and
	// one a user configures explicitly. It is the rule equivalent of a
	// detector embedding detectors.EndpointSetter.
	//
	// Leave it zero for a provider with one fixed verification URL - most
	// rules do.
	Endpoint EndpointConfig
}

// endpointCaptureName is the reserved key an endpoint is stored under in a
// candidate's Captures, and the name the HTTP verifier recognises to mean
// "this is the base address, not a value to fill into a fixed one".
const endpointCaptureName = "endpoint"

// EndpointConfig describes the addresses a rule can verify a credential
// against, beyond the single fixed URL most rules use.
//
// When configured, HTTP.URL stops being a full URL template and becomes a
// path joined onto whichever endpoint is being tried - the same thing
// url.JoinPath(baseURL, path) does in a hand-written detector. That is a
// deliberate difference from every other value a rule substitutes: an
// endpoint is meant to choose where the request goes, not fill in part of
// an address the rule author already fixed.
type EndpointConfig struct {
	// Pattern finds a candidate endpoint URL in the scanned data itself,
	// for a provider whose address is not known in advance. Its Name must
	// be left empty: a found endpoint is always captured under the
	// reserved name "endpoint".
	//
	// Unlike Rule.Patterns, finding nothing here never stops the rule
	// from reporting a candidate - the cloud address or a user-configured
	// one may cover it instead. Leave it nil for a provider with no
	// self-hosted option.
	Pattern *Pattern

	// Cloud is the provider's own hosted address. Leave it empty for a
	// provider with no cloud offering of its own, such as a self-hosted
	// only tool - that is not an omission, HashiCorp Vault has none either.
	Cloud string
}

// configured reports whether a rule declares any endpoint handling at all.
// A rule for which this is false behaves exactly as it did before Endpoint
// existed: one request, to the fixed URL in HTTP.URL.
func (e EndpointConfig) configured() bool {
	return e.Pattern != nil || e.Cloud != ""
}

const (
	// defaultChunkSpan is how much of the chunk a rule with one pattern is
	// handed either side of the keyword, by default. It matches what a
	// hand-written detector gets without lifting a finger: the engine's own
	// default span around a keyword match, for a detector that implements no
	// interface asking for more. See defaultOffsetRadius in
	// pkg/engine/ahocorasick.
	defaultChunkSpan = 512

	// multiPatternChunkSpan is the same for a rule with more than one
	// pattern. An ID declared near the top of a config file and its key
	// declared near the bottom are one credential, and a window sized for a
	// single token would see only one of them and report nothing - which is
	// exactly why a hand-written detector with more than one part embeds
	// detectors.DefaultMultiPartCredentialProvider for a wider span. A rule
	// with more than one pattern needs the same thing, so it gets the same
	// number automatically rather than every such rule repeating it.
	multiPatternChunkSpan = 1024
)

// chunkSpan is how much of the chunk this rule is handed around a keyword.
// The rule's own MaxChunkSpan wins when it sets one; otherwise it follows
// from how many patterns make up the credential.
func (r Rule) chunkSpan() int64 {
	if r.MaxChunkSpan > 0 {
		return r.MaxChunkSpan
	}
	if len(r.Patterns) > 1 {
		return multiPatternChunkSpan
	}
	return defaultChunkSpan
}
