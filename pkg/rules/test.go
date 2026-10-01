// This file holds the data a rule's tests run from: Test and its two parts,
// and SampleText, which turns a set of values into text shaped the way this
// rule expects to find a credential.

package rules

import (
	"fmt"
	"strings"
)

// Test is the data a rule's tests run from. It lives on the rule so that a
// detector and the proof it works sit in one place, and so a rule arriving
// without proof is a visible hole rather than a missing file somewhere else.
//
// There is one field per kind of test, and one test file reading each:
//
//	Detection    detection_test.go    what the rule finds, offline
//	Integration  integration_test.go  what the provider says, live
//
// Nothing here is used during a scan. Keep the values obviously fake: they are
// compiled into the binary like any other field.
type Test struct {
	Detection   DetectionTest
	Integration IntegrationTest
}

// DetectionTest is what a rule should and should not find. It needs no network,
// so it is the test every rule has.
//
// Only values are stored here, never text and never expected findings. The test
// writes the text, and the findings follow from the values: SecretID and
// FullSecretID are templates over pattern names, so filling them from Examples
// gives exactly what the rule must report.
type DetectionTest struct {
	// Examples is one value per pattern that the rule must capture, keyed by
	// pattern name. The test builds text around these and checks the rule
	// finds exactly them.
	//
	// It also derives the negatives it can work out on its own: each example
	// removed in turn, since every pattern is required, and for a
	// DistinctCaptures rule the same value in two slots.
	Examples map[string]string

	// NotExamples are values a pattern must refuse, keyed by pattern name.
	// Each is swapped in for that pattern's example, and the rule must then
	// find nothing.
	//
	// Write them one character off the boundary. A sample far outside the
	// pattern still passes after the pattern has been loosened by mistake,
	// which is the bug these exist to catch.
	NotExamples map[string][]string
}

// IntegrationTest points at credentials held in the project's secret manager,
// for the live test that asks the provider whether verification really works.
// Only field names are stored here, never the credentials themselves. Leave it
// zero for a rule with no live test.
type IntegrationTest struct {
	// Group is the secret group the fields live in, such as "detectors5".
	Group string

	// Valid and Invalid name the fields whose values together make up one
	// working, and one revoked, credential.
	//
	// They are lists rather than one field per pattern because that is how
	// the stored secrets are actually shaped: some hold the whole credential
	// in a single field, and some split it across two. The test pastes the
	// values it is given into one piece of text and lets the patterns find
	// them, the same way a real scan would.
	Valid   []string
	Invalid []string
}

// SampleText builds a piece of text holding values, shaped the way this rule
// expects to find a credential: each value introduced by one of the rule's
// keywords and sitting close behind it, because most patterns are built with
// detectors.PrefixRegex and will not look further than that.
//
// It exists for the tests in pkg/rules/builtin/test, so what a rule's tests
// check it against is built one way instead of each test writing its own
// text. Values naming a pattern this rule does not declare are skipped, and
// so are patterns with no value, which is what lets a test build "the same
// text but with one half missing".
//
// An "endpoint" value is written the same way, if this rule has an
// Endpoint.Pattern and the caller supplied one — otherwise a rule that must
// find an endpoint to report anything would never be exercised by a detection
// test built only from its required patterns.
func (r Rule) SampleText(values map[string]string) string {
	keyword := ""
	if len(r.Keywords) > 0 {
		keyword = r.Keywords[0]
	}
	var out strings.Builder
	for _, pattern := range r.Patterns {
		value, ok := values[pattern.Name]
		if !ok {
			continue
		}
		fmt.Fprintf(&out, "%s %s = %s\n", keyword, pattern.Name, value)
	}
	if r.Endpoint.Pattern != nil {
		if value, ok := values[endpointCaptureName]; ok {
			fmt.Fprintf(&out, "%s %s = %s\n", keyword, endpointCaptureName, value)
		}
	}
	return out.String()
}
