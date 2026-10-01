// What each rule finds, run from its Test.Detection. No network, so every rule
// has this test.
//
// A rule stores values, never text and never expected findings. Both live here.
// The text is a handful of shapes a credential turns up in, shared by every
// rule and filled with that rule's own examples, so adding a rule adds no
// prose. The expected findings follow from the values, because SecretID and
// FullSecretID are templates over pattern names.
//
// Three questions, one per test: does a rule find its credential in each shape,
// does it still do so with every other rule's credentials in the same text, and
// does it refuse the things it should.

package test

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules/builtin"
)

// update rewrites the golden file instead of comparing against it:
//
//	go test ./pkg/rules/builtin/test -run TestFindingIdentities -update
var update = flag.Bool("update", false, "rewrite testdata/findings.txt")

const goldenPath = "testdata/findings.txt"

// shapes are the surroundings a credential is found in: on its own, buried in a
// config file, in the middle of a log. Each holds one %s for the sample text.
//
// They are here rather than on each rule because they have nothing to do with
// any particular provider, and because every rule should survive all of them.
// None contains a credential of its own, which TestShapesHoldNoCredential
// checks.
var shapes = []string{
	"%s",

	`# Configuration File: config.yaml
	database:
		host: $DB_HOST
		port: $DB_PORT
		username: $DB_USERNAME
		password: $DB_PASS  # IMPORTANT: Do not share this password publicly

	api:
		auth_type: "API-Key"
		base_url: "https://api.collect2.com/v1/user?id=22f39f53-3bd4-d84b-8e29-00402d5c316f"
%s
	# Notes:
	# - Remember to rotate the secret every 90 days.
	# - The above credentials should only be used in a secure environment.
`,

	`[INFO]  2024-04-02T11:15:03Z starting worker pool size=8
[DEBUG] 2024-04-02T11:15:03Z loading credentials from environment
%s
[WARN]  2024-04-02T11:15:04Z retrying request attempt=2 backoff=500ms
[ERROR] 2024-04-02T11:15:09Z request failed status=401 body="unauthorized"
`,
}

// TestDetection checks that every rule finds its own credential in every shape,
// and reports it under the identity it is stored by.
func TestDetection(t *testing.T) {
	for _, rule := range builtin.All {
		t.Run(ruleKey(rule), func(t *testing.T) {
			detector := rules.New(rule, nil)
			sample := rule.SampleText(rule.Test.Detection.Examples)
			want := identity(rule, rule.Test.Detection.Examples)

			for _, shape := range shapes {
				text := fmt.Sprintf(shape, sample)
				got := findingsIn(t, detector, text)
				if !slices.Contains(got, want) {
					t.Errorf("%.20q...:\n found %v\n want  %v", shape, shorten(got), shorten([]string{want}))
				}
				for _, finding := range got {
					if !builtFromExamples(rule, finding) {
						t.Errorf("%.20q...: reported %v, which is not built from this rule's examples",
							shape, shorten([]string{finding}))
					}
				}
			}
		})
	}
}

// TestDetectionWithEveryOtherCredential puts every rule's credential in one
// document and runs every rule over all of it.
//
// This is the test a rule cannot pass alone: a pattern loose enough to match
// another provider's key pairs the wrong halves together, and reports a
// credential that was never in the data. Per-rule tests never see it, because
// each one only ever reads text written for itself.
func TestDetectionWithEveryOtherCredential(t *testing.T) {
	var document strings.Builder
	for _, rule := range builtin.All {
		fmt.Fprintf(&document, shapes[1], rule.SampleText(rule.Test.Detection.Examples))
	}
	text := document.String()

	for _, rule := range builtin.All {
		t.Run(ruleKey(rule), func(t *testing.T) {
			got := findingsIn(t, rules.New(rule, nil), text)
			if want := identity(rule, rule.Test.Detection.Examples); !slices.Contains(got, want) {
				t.Errorf("lost its own credential among the others:\n found %v\n want  %v",
					shorten(got), shorten([]string{want}))
			}
			for _, finding := range got {
				if !builtFromExamples(rule, finding) {
					t.Errorf("reported %v, which belongs to another rule", shorten([]string{finding}))
				}
			}
		})
	}
}

// TestRefusals takes each rule's credential apart in the ways a rule should
// refuse, and expects nothing back.
func TestRefusals(t *testing.T) {
	for _, rule := range builtin.All {
		t.Run(ruleKey(rule), func(t *testing.T) {
			detector := rules.New(rule, nil)
			examples := rule.Test.Detection.Examples

			refusals := 0
			refuse := func(name, text string) {
				refusals++
				if got := findingsIn(t, detector, text); len(got) > 0 {
					t.Errorf("%s: expected nothing, found %v", name, shorten(got))
				}
			}

			// Every pattern is required, so removing any one half leaves
			// something that is not a credential.
			if len(rule.Patterns) > 1 {
				for _, pattern := range rule.Patterns {
					short := maps.Clone(examples)
					delete(short, pattern.Name)
					refuse("without "+pattern.Name, rule.SampleText(short))
				}
			}

			// One string cannot be both halves of a credential. See
			// Rule.DistinctCaptures.
			if rule.DistinctCaptures {
				same := map[string]string{}
				for _, pattern := range rule.Patterns {
					same[pattern.Name] = examples[rule.Patterns[0].Name]
				}
				refuse("one value in every slot", rule.SampleText(same))
			}

			// The near misses only the rule author knows about.
			for name, values := range rule.Test.Detection.NotExamples {
				for _, value := range values {
					swapped := maps.Clone(examples)
					swapped[name] = value
					refuse(name+" near miss", rule.SampleText(swapped))
				}
			}

			t.Logf("%d text(s) refused", refusals)
		})
	}
}

// TestShapesHoldNoCredential checks the shared text itself is clean. A shape
// that happens to contain something a rule matches would make every finding
// above suspect.
func TestShapesHoldNoCredential(t *testing.T) {
	for _, rule := range builtin.All {
		detector := rules.New(rule, nil)
		for _, shape := range shapes {
			text := fmt.Sprintf(shape, "")
			if got := findingsIn(t, detector, text); len(got) > 0 {
				t.Errorf("%s matched the empty shape %.20q...: %v", rule.Type, shape, shorten(got))
			}
		}
	}
}

// TestEveryRuleIsTested makes missing test data a failure rather than a test
// that quietly checks nothing.
//
// Validate proves an example matches its pattern, but it cannot insist one
// exists — a rule built ad hoc elsewhere has no reason to carry test data.
// Shipping in All is what makes it required.
func TestEveryRuleIsTested(t *testing.T) {
	for _, rule := range builtin.All {
		for _, pattern := range rule.Patterns {
			if rule.Test.Detection.Examples[pattern.Name] == "" {
				t.Errorf("%s has no test example for pattern %q", rule.Type, pattern.Name)
			}
		}
	}
}

// TestFindingIdentities compares what every rule reports a credential under
// against a checked-in list.
//
// The other tests cannot catch this. They work out what to expect from the
// rule's own SecretID and FullSecretID, so editing either template moves the
// expectation with it and the test still passes. The list has to be stored
// somewhere the rule cannot reach.
//
// This matters more than it looks: both templates are hashed into the record a
// finding is written to, so changing one for an existing detector does not
// merely alter this scan — it makes every record already stored under the old
// value unreachable. A deliberate change is fine, and regenerating the file
// with -update makes it a line in a review rather than a silent one.
func TestFindingIdentities(t *testing.T) {
	var current strings.Builder
	for _, rule := range builtin.All {
		fmt.Fprintf(&current, "%s\t%s\n", ruleKey(rule), identity(rule, rule.Test.Detection.Examples))
	}

	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(current.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("wrote " + goldenPath)
		return
	}

	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (run the test with -update to create it)", err)
	}
	if current.String() != string(golden) {
		t.Errorf("what rules report findings under has changed.\n"+
			"Check every line below is a change you meant, then rerun with -update.\n"+
			"--- stored\n%s--- now\n%s", golden, current.String())
	}
}

// identity is what a rule reports one credential under: its SecretID and
// FullSecretID with the values filled in.
//
// Findings are compared by this rather than by what was captured, because this
// is the part that must not drift: both halves are hashed into the record a
// finding is written to, so changing either one strands what is already stored.
//
// The templates are filled in here instead of by calling the rules package,
// so a mistake in that package's own template code cannot cancel itself out.
func identity(rule rules.Rule, values map[string]string) string {
	fill := func(template string) string {
		for name, value := range values {
			template = strings.ReplaceAll(template, "{"+name+"}", value)
		}
		return template
	}
	// A single-pattern rule need not name its SecretID; there is nothing else
	// it could be.
	secretID := rule.SecretID
	if secretID == "" {
		secretID = "{" + rule.Patterns[0].Name + "}"
	}
	return fill(secretID) + "|" + fill(rule.FullSecretID)
}

// builtFromExamples reports whether a finding is made only of the values this
// rule declared, plus whatever fixed text its own SecretID and FullSecretID
// templates put around them. It is how "and nothing else" is checked: a rule
// that paired its key with a string from elsewhere in the text leaves that
// string behind.
//
// Most rules put nothing but placeholders in those templates, so stripping
// every example value used to leave nothing behind but the "|" identity
// joins Raw and RawV2 with. A rule whose FullSecretID also carries a fixed
// separator - such as "{key}:{endpoint}", reproducing a hand-written
// detector's own RawV2 format - would leave that separator behind too, so
// what counts as "nothing else" is worked out from the templates themselves
// rather than assumed to be empty.
func builtFromExamples(rule rules.Rule, finding string) bool {
	noValues := make(map[string]string, len(rule.Test.Detection.Examples))
	for name := range rule.Test.Detection.Examples {
		noValues[name] = ""
	}
	skeleton := identity(rule, noValues)

	for _, value := range rule.Test.Detection.Examples {
		if value == "" {
			continue
		}
		finding = strings.ReplaceAll(finding, value, "")
	}
	return finding == skeleton
}

// findingsIn runs the detector over text and returns the identity of each
// result, sorted, since results have no meaningful order.
func findingsIn(t *testing.T, detector detectors.Detector, text string) []string {
	t.Helper()
	results, err := detector.FromData(context.Background(), false, []byte(text))
	if err != nil {
		t.Fatalf("scanning sample text: %v", err)
	}
	out := make([]string, 0, len(results))
	for _, r := range results {
		out = append(out, string(r.Raw)+"|"+string(r.RawV2))
	}
	sort.Strings(out)
	return out
}

// shorten trims values for a readable failure message. Only the printout is
// shortened; the comparisons above use the values in full, because a 150-
// character capture and a 148-character one must not look the same.
func shorten(findings []string) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		if len(finding) > 40 {
			finding = finding[:40] + "..."
		}
		out = append(out, finding)
	}
	return out
}
