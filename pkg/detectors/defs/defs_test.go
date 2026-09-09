package defs

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/abuseipdb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aylien"
	godaddyv1 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/godaddy/v1"
	godaddyv2 "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/godaddy/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/launchdarkly"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/stripe"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestAllValidate(t *testing.T) {
	for _, r := range All {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.Type, err)
		}
	}
}

// replaced pairs each rule with the hand-written detector it stands in for.
var replacements = []struct {
	name       string
	goDetector detectors.Detector
	rule       rules.Rule
	inputs     []string

	// knownDifferences names comparisons where this rule deliberately does
	// not match the detector it replaces, mapped to why. Anything not listed
	// here must match exactly, and anything listed must actually still
	// differ, so an entry cannot quietly outlive the reason for it.
	//
	// Raw and RawV2 can never be listed here. They are hashed into the
	// identifier a finding is stored under, so a rule that changes them
	// strands every record written under the old value.
	knownDifferences map[string]string
}{
	{
		name:       "sendgrid",
		goDetector: sendgrid.Scanner{},
		rule:       SendGrid,
		inputs: []string{
			"sendgrid token = 'SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9c9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I'",
			"sendgrid token = 'SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9c9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I' | 'SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9c9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I'",
			"sendgrid = 'SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9?9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I'",
			"no secret here at all",
		},
	},
	{
		name:       "stripe",
		goDetector: stripe.Scanner{},
		rule:       Stripe,
		inputs: []string{
			"stripe token = 'rk_live_HUOlkIKhNEYOPS0oDSwGwJHbg4xGaXNeJZ2CdvDGeVZQHljoq5TuFwQHgME3W'",
			"stripe token = '?k_live_HUOlkIKhNEYOPS0oDSwGwJHbg4xGaXNeJZ2CdvDGeVZQHljoq5TuFwQHgME3?'",
			"sk_live_abcdefghijklmnopqrstuvwxyz0123456789 and rk_live_ZZZZZZZZZZZZZZZZZZZZZZ",
		},
	},
	{
		name:       "abuseipdb",
		goDetector: abuseipdb.Scanner{},
		rule:       AbuseIPDB,
		inputs: []string{
			"\n[INFO] Sending request to abuseipdb API\n[DEBUG] Using API_KEY=o8oqti3tghu2xic76ii4t7jb9bxuzd4200j1yrkdjl6s8834hx4dgz1wwo90diqraakjd13sljcjkfnf\n[INFO] Response received: 200 OK\n",
			"abuseipdb key = tooshort",
			"unrelated text with abuseipdb mentioned but no key",
		},
	},
	{
		name:       "godaddy-ote",
		goDetector: &godaddyv1.Scanner{},
		rule:       GoDaddyOTE,
		knownDifferences: map[string]string{
			"secretParts": "the hand-written detector omits the secret half of the " +
				"credential from SecretParts, which analyzers and secret storage read",
		},
		inputs: []string{
			"godaddy key: abcdefghijklmnopqrstuvwxyz0123456789A godaddy secret: abcdefghijklmnopqrstuv",
			"godaddy key = tooshort and godaddy secret = alsoshort",
			"nothing about this provider here",
		},
	},
	{
		name:       "godaddy-prod",
		goDetector: &godaddyv2.Scanner{},
		rule:       GoDaddyProd,
		knownDifferences: map[string]string{
			"secretParts": "the hand-written detector omits the secret half of the " +
				"credential from SecretParts, which analyzers and secret storage read",
		},
		inputs: []string{
			"godaddy key: abcdefghijklmnopqrstuvwxyz012345678 godaddy secret: abcdefghijklmnopqrstuv",
			"godaddy key = tooshort and godaddy secret = alsoshort",
		},
	},
	{
		name:       "launchdarkly",
		goDetector: launchdarkly.Scanner{},
		rule:       LaunchDarkly,
		inputs: []string{
			"LD_TOKEN = api-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
			"sdk key: sdk-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
			"mob-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d is a public client key",
			"api-not-a-uuid",
		},
	},
	{
		name:       "aylien",
		goDetector: aylien.Scanner{},
		rule:       Aylien,
		inputs: []string{
			"\n# do not share these credentials\naylien credentials:\n\taylien key: cr479du2l9pkmhar8gw5hufofvwp86q9\n\taylien id: y3ejw028\n# valid till Dec 2025\n",
			"aylien key: cr479du2l9pkmhar8gw5hufofvwp86q9",
			"aylien id: y3ejw028",
		},
	},
}

// TestDetectionParity checks that each rule finds exactly what the detector it
// replaces finds, using the engine's own pre-filter and inputs taken from that
// detector's test file.
func TestDetectionParity(t *testing.T) {
	ctx := context.Background()
	for _, tc := range replacements {
		t.Run(tc.name, func(t *testing.T) {
			ruleDetector := rules.New(tc.rule, http.DefaultClient)
			// Guards against a test that proves nothing: if none of the inputs
			// match, both implementations return nothing and every comparison
			// below passes for the wrong reason.
			foundSomething := false
			// Which declared differences actually showed up.
			observedDifferences := map[string]bool{}

			// The keyword pre-filter has to agree, or the engine would hand
			// the two implementations different chunks to work on.
			if got, want := sortedCopy(ruleDetector.Keywords()), sortedCopy(tc.goDetector.Keywords()); !slices.Equal(got, want) {
				t.Errorf("keywords differ:\n go   %v\n rule %v", want, got)
			}
			if ruleDetector.Type() != tc.goDetector.Type() {
				t.Errorf("type differs: go=%v rule=%v", tc.goDetector.Type(), ruleDetector.Type())
			}

			acGo := ahocorasick.NewAhoCorasickCore([]detectors.Detector{tc.goDetector})
			acRule := ahocorasick.NewAhoCorasickCore([]detectors.Detector{ruleDetector})

			for _, input := range tc.inputs {
				fromGoDetector, err := tc.goDetector.FromData(ctx, false, []byte(input))
				if err != nil {
					t.Fatalf("go detector: %v", err)
				}
				fromRule, err := ruleDetector.FromData(ctx, false, []byte(input))
				if err != nil {
					t.Fatalf("rule: %v", err)
				}
				if a, b := len(acGo.FindDetectorMatches([]byte(input))), len(acRule.FindDetectorMatches([]byte(input))); a != b {
					t.Errorf("pre-filter disagrees on %q: go=%d rule=%d", truncate(input), a, b)
				}
				if len(fromRule) > 0 {
					foundSomething = true
				}
				compare(t, tc.knownDifferences, observedDifferences, "rawValues", input,
					rawValues(fromGoDetector), rawValues(fromRule))
				// Analyzers and secret storage read SecretParts, so it has to
				// match too, not just the raw values.
				compare(t, tc.knownDifferences, observedDifferences, "secretParts", input,
					secretPartsOf(fromGoDetector), secretPartsOf(fromRule))
				// ExtraData is reported to the user, and some detectors only
				// populate it once a credential is confirmed live, so it has to
				// match on the unverified path too.
				compare(t, tc.knownDifferences, observedDifferences, "extraData", input,
					extraDataOf(fromGoDetector), extraDataOf(fromRule))
			}
			if !foundSomething {
				t.Error("no input matched, so this case compared nothing")
			}
			// A declared difference that never happens is a leftover, and
			// leaving it would mask a real regression in that aspect later.
			for aspect, reason := range tc.knownDifferences {
				if !observedDifferences[aspect] {
					t.Errorf("%s never differed, so this entry can be removed: %s", aspect, reason)
				}
			}
		})
	}
}

// TestReplacePreservesOptionalInterfaces guards the main hazard in swapping an
// implementation: the engine reads optional interfaces off a detector to decide
// how much chunk data to hand it and how to identify it. A rule that omits an
// interface the original implements would change scanning behaviour silently,
// so a detector implementing one may only be replaced by a rule that
// implements it the same way.
// TestIdentityFieldsMatchOriginal checks Raw and RawV2 individually, rather
// than through the combined view the parity test uses, because these two are
// what a finding is stored under. A rule that changes either one orphans
// records already written by the detector it replaces.
func TestIdentityFieldsMatchOriginal(t *testing.T) {
	ctx := context.Background()
	for _, tc := range replacements {
		t.Run(tc.name, func(t *testing.T) {
			ruleDetector := rules.New(tc.rule, nil)
			for _, input := range tc.inputs {
				fromGo, err := tc.goDetector.FromData(ctx, false, []byte(input))
				if err != nil {
					t.Fatal(err)
				}
				fromRule, err := ruleDetector.FromData(ctx, false, []byte(input))
				if err != nil {
					t.Fatal(err)
				}
				if a, b := identities(fromGo), identities(fromRule); !slices.Equal(a, b) {
					t.Errorf("stored identity differs for %q:\n go   %v\n rule %v",
						truncate(input), a, b)
				}
			}
		})
	}
}

// identities pairs each result's Raw with its RawV2 exactly as stored, so an
// empty RawV2 is distinguishable from one that merely repeats Raw.
func identities(results []detectors.Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, fmt.Sprintf("raw=%s|rawv2=%s", r.Raw, r.RawV2))
	}
	sort.Strings(out)
	return out
}

func TestReplacePreservesOptionalInterfaces(t *testing.T) {
	for _, tc := range replacements {
		t.Run(tc.name, func(t *testing.T) {
			ruleDetector := rules.New(tc.rule, nil)

			goSpan, goOK := tc.goDetector.(detectors.MultiPartCredentialProvider)
			ruleSpan, ruleOK := ruleDetector.(detectors.MultiPartCredentialProvider)
			if goOK != ruleOK {
				t.Fatalf("MultiPartCredentialProvider: go=%v rule=%v", goOK, ruleOK)
			}
			if goOK && goSpan.MaxCredentialSpan() != ruleSpan.MaxCredentialSpan() {
				t.Errorf("MaxCredentialSpan: go=%d rule=%d",
					goSpan.MaxCredentialSpan(), ruleSpan.MaxCredentialSpan())
			}

			goVer, goOK := tc.goDetector.(detectors.Versioner)
			ruleVer, ruleOK := ruleDetector.(detectors.Versioner)
			if goOK != ruleOK {
				t.Fatalf("Versioner: go=%v rule=%v", goOK, ruleOK)
			}
			if goOK && goVer.Version() != ruleVer.Version() {
				t.Errorf("Version: go=%d rule=%d", goVer.Version(), ruleVer.Version())
			}

			// Endpoint customization has no equivalent in a rule yet, so a
			// detector that supports it cannot be replaced without losing
			// user-configured and discovered endpoints.
			if _, ok := tc.goDetector.(detectors.EndpointCustomizer); ok {
				t.Error("detector supports endpoint customization, which a rule cannot express")
			}
			if _, ok := tc.goDetector.(detectors.CustomResultsCleaner); ok {
				t.Error("detector has a custom results cleaner, which a rule cannot express")
			}
			if _, ok := tc.goDetector.(detectors.CustomFalsePositiveChecker); ok {
				t.Error("detector has a custom false positive checker, which a rule cannot express")
			}
		})
	}
}

// TestReplaceSubstitutesInPlace checks that Replace swaps matching detectors,
// leaves everything else alone, and does not change the length or order of the
// list, since the engine keys detectors by type and version.
func TestReplaceSubstitutesInPlace(t *testing.T) {
	base := defaults.DefaultDetectors()
	got := Replace(base, nil)

	if len(got) != len(base) {
		t.Fatalf("Replace changed the detector count: %d -> %d", len(base), len(got))
	}

	swapped := 0
	for i := range base {
		if got[i] == base[i] {
			continue
		}
		swapped++
		if got[i].Type() != base[i].Type() {
			t.Errorf("index %d: replaced %v with %v", i, base[i].Type(), got[i].Type())
		}
	}
	if swapped != len(All) {
		t.Errorf("swapped %d detectors, want %d", swapped, len(All))
	}
}

// TestReplaceIsNoopWithoutMatches checks that detectors with no corresponding
// rule are returned untouched.
func TestReplaceIsNoopWithoutMatches(t *testing.T) {
	in := []detectors.Detector{stubDetector{}}
	got := Replace(in, nil)
	if len(got) != 1 || got[0] != in[0] {
		t.Error("Replace modified a detector it has no rule for")
	}
}

type stubDetector struct{}

func (stubDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, nil
}
func (stubDetector) Keywords() []string { return []string{"stub"} }
func (stubDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Generic
}
func (stubDetector) Description() string { return "stub" }

func TestDetectorsBuildsAllRules(t *testing.T) {
	if got := Detectors(http.DefaultClient); len(got) != len(All) {
		t.Fatalf("got %d detectors, want %d", len(got), len(All))
	}
}

// compare asserts that one aspect of the two implementations matches, unless
// the case declares it as a reviewed difference. It records which declared
// differences were actually observed so the caller can spot stale entries.
//
// An input that matches nothing produces no difference, which is why staleness
// is judged across the whole case rather than per input.
func compare(t *testing.T, known map[string]string, seen map[string]bool, aspect, input string, fromGo, fromRule []string) {
	t.Helper()
	_, expectedToDiffer := known[aspect]
	if aspect == identityAspect && expectedToDiffer {
		t.Fatalf("%s cannot be waived: it is the stored identity of a finding", aspect)
	}
	differs := !slices.Equal(fromGo, fromRule)

	if differs {
		seen[aspect] = true
	}
	if differs && !expectedToDiffer {
		t.Errorf("%s differs for %q:\n go   %v\n rule %v", aspect, truncate(input), fromGo, fromRule)
	}
}

// identityAspect is the comparison covering Raw and RawV2, the pair a finding
// is stored under. It is the one aspect a rule may never differ on.
const identityAspect = "rawValues"

// rawValues returns the identifying value of each result: RawV2 when a rule
// sets one, and Raw otherwise. That mirrors how a reader tells two findings
// apart. Sorted, because result order is not part of what is being compared.
func rawValues(results []detectors.Result) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		if len(r.RawV2) > 0 {
			out = append(out, string(r.RawV2))
		} else {
			out = append(out, string(r.Raw))
		}
	}
	sort.Strings(out)
	return out
}

// secretPartsOf flattens each result's SecretParts into one comparable string,
// since maps cannot be compared directly and the key order is not meaningful.
func secretPartsOf(results []detectors.Result) []string {
	return flattenMaps(results, func(r detectors.Result) map[string]string { return r.SecretParts })
}

// extraDataOf does the same for ExtraData.
func extraDataOf(results []detectors.Result) []string {
	return flattenMaps(results, func(r detectors.Result) map[string]string { return r.ExtraData })
}

// flattenMaps turns one map per result into one sorted "k=v|k=v" string per
// result, then sorts those, so two result sets can be compared regardless of
// map iteration order or result order.
func flattenMaps(results []detectors.Result, pick func(detectors.Result) map[string]string) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		m := pick(r)
		if m == nil {
			// A nil map and an empty one are not the same thing downstream:
			// one prints as null in JSON output and the other as {}.
			out = append(out, "<nil>")
			continue
		}
		pairs := make([]string, 0, len(m))
		for k, v := range m {
			pairs = append(pairs, k+"="+v)
		}
		sort.Strings(pairs)
		out = append(out, strings.Join(pairs, "|"))
	}
	sort.Strings(out)
	return out
}

// sortedCopy sorts without disturbing the caller's slice, which for Keywords
// is the detector's own state.
func sortedCopy(values []string) []string {
	out := slices.Clone(values)
	sort.Strings(out)
	return out
}

// truncate keeps failure messages readable when an input is a long multi-line
// chunk.
func truncate(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
