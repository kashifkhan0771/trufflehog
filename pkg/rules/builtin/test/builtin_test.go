// Tests for the shared parts of this package: that every rule is valid, and
// that Replace and Detectors hand the engine what it expects.

package test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/sendgrid"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules/builtin"
)

// TestAllValidate is the first thing to fail when a rule is malformed, since
// New panics on an invalid rule and would otherwise take every other test with
// it.
func TestAllValidate(t *testing.T) {
	for _, r := range builtin.All {
		// Every problem Validate reports already names its own rule (type,
		// plus version when set), so nothing needs adding here - that
		// matters once more than one rule in this loop is broken at once.
		if err := r.Validate(); err != nil {
			t.Error(err)
		}
	}
}

// TestReplaceSubstitutesInPlace checks that Replace swaps matching detectors,
// leaves everything else alone, and does not change the length or order of the
// list, since the engine keys detectors by type and version.
func TestReplaceSubstitutesInPlace(t *testing.T) {
	base := defaults.DefaultDetectors()
	got := builtin.Replace(base, nil)

	if len(got) != len(base) {
		t.Fatalf("Replace changed the detector count: %d -> %d", len(base), len(got))
	}

	// Not every rule has a match to swap: a detector behind a feature flag
	// that defaults off, such as the HashiCorp Vault ones, is simply absent
	// from base in this environment. The expected count is therefore how
	// many of base's own entries a rule exists for, not len(builtin.All).
	ruleKeys := make(map[detectorKey]bool, len(builtin.All))
	for _, rule := range builtin.All {
		ruleKeys[detectorKey{detectorType: rule.Type, version: rule.Version}] = true
	}
	wantSwapped := 0
	for _, d := range base {
		if ruleKeys[keyFor(d)] {
			wantSwapped++
		}
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
	if swapped != wantSwapped {
		t.Errorf("swapped %d detectors, want %d", swapped, wantSwapped)
	}
}

// TestReplaceIsNoopWithoutMatches checks that detectors with no corresponding
// rule are returned untouched.
func TestReplaceIsNoopWithoutMatches(t *testing.T) {
	in := []detectors.Detector{stubDetector{}}
	got := builtin.Replace(in, nil)
	if len(got) != 1 || got[0] != in[0] {
		t.Error("Replace modified a detector it has no rule for")
	}
}

func TestDetectorsBuildsAllRules(t *testing.T) {
	if got := builtin.Detectors(http.DefaultClient); len(got) != len(builtin.All) {
		t.Fatalf("got %d detectors, want %d", len(got), len(builtin.All))
	}
}

// A disabled rule takes its provider out of the scan altogether: the
// hand-written detector goes with it, so nothing is left looking for that
// provider. This checks the removal, since the alternative reading — quietly
// falling back to the hand-written detector — looks identical from the outside
// until someone inspects the list.
func TestDisabledRuleRemovesTheDetector(t *testing.T) {
	// A copy, so the package's own rule is untouched for the other tests.
	off := builtin.SendGrid
	off.Disabled = true
	original := builtin.All
	builtin.All = append([]rules.Rule{off}, allExcept(builtin.SendGrid.Type, builtin.SendGrid.Version)...)
	defer func() { builtin.All = original }()

	handWritten := sendgrid.Scanner{}
	stub := stubDetector{}

	got := builtin.Replace([]detectors.Detector{handWritten, stub}, nil)
	if len(got) != 1 {
		t.Fatalf("expected the SendGrid detector to be dropped, got %d detectors", len(got))
	}
	if got[0].Type() != stub.Type() {
		t.Errorf("the wrong detector was dropped: %s survived", got[0].Type())
	}

	for _, d := range builtin.Detectors(nil) {
		if d.Type() == builtin.SendGrid.Type {
			t.Error("Detectors built a disabled rule")
		}
	}
}

// TestReplacePreservesOptionalInterfaces guards the main hazard in swapping an
// implementation: the engine reads optional interfaces off a detector to decide
// how much chunk data to hand it and how to identify it. A rule that omits an
// interface the original implements would change scanning behaviour silently,
// so a detector implementing one may only be replaced by a rule that implements
// it the same way.
//
// The credential span is the exception. Every rule declares one, whether or not
// the detector it replaces did, so the check is that the window never gets
// narrower: a wider window finds everything the old one did, while a narrower
// one can miss a credential the old detector reported.
func TestReplacePreservesOptionalInterfaces(t *testing.T) {
	handWritten := byKey(defaults.DefaultDetectors())

	for _, tc := range builtin.All {
		t.Run(ruleKey(tc), func(t *testing.T) {
			ruleDetector := rules.New(tc, nil)
			goDetector, ok := handWritten[keyFor(ruleDetector)]
			if !ok {
				t.Skip("no hand-written detector to compare against")
			}

			ruleSpan, ok := ruleDetector.(detectors.MultiPartCredentialProvider)
			if !ok {
				t.Fatal("every rule should declare a credential span")
			}
			if goSpan, ok := goDetector.(detectors.MultiPartCredentialProvider); ok {
				if ruleSpan.MaxCredentialSpan() < goSpan.MaxCredentialSpan() {
					t.Errorf("MaxCredentialSpan narrowed: go=%d rule=%d",
						goSpan.MaxCredentialSpan(), ruleSpan.MaxCredentialSpan())
				}
			}

			goVer, goOK := goDetector.(detectors.Versioner)
			ruleVer, ruleOK := ruleDetector.(detectors.Versioner)
			if goOK != ruleOK {
				t.Fatalf("Versioner: go=%v rule=%v", goOK, ruleOK)
			}
			if goOK && goVer.Version() != ruleVer.Version() {
				t.Errorf("Version: go=%d rule=%d", goVer.Version(), ruleVer.Version())
			}

			// A detector that supports endpoint customization can only be
			// replaced by a rule that declares Endpoint: otherwise the
			// swap would silently stop verifying against the provider's
			// cloud address and any address found in scanned data.
			if _, ok := goDetector.(detectors.EndpointCustomizer); ok {
				if _, ruleOK := ruleDetector.(detectors.EndpointCustomizer); !ruleOK {
					t.Error("detector supports endpoint customization, but the rule does not declare Endpoint")
				}
			}
			if _, ok := goDetector.(detectors.CustomResultsCleaner); ok {
				t.Error("detector has a custom results cleaner, which a rule cannot express")
			}
			if _, ok := goDetector.(detectors.CustomFalsePositiveChecker); ok {
				t.Error("detector has a custom false positive checker, which a rule cannot express")
			}
		})
	}
}

// stubDetector stands in for a detector this package has no rule for.
type stubDetector struct{}

func (stubDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, nil
}

func (stubDetector) Keywords() []string { return []string{"stub"} }

func (stubDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Generic
}

func (stubDetector) Description() string { return "stub" }

// allExcept returns All without the rule of this type and version.
func allExcept(detectorType detector_typepb.DetectorType, version int) []rules.Rule {
	kept := make([]rules.Rule, 0, len(builtin.All))
	for _, rule := range builtin.All {
		if rule.Type == detectorType && rule.Version == version {
			continue
		}
		kept = append(kept, rule)
	}
	return kept
}

// ruleKey names a rule the way the engine identifies it, by type and version,
// so two versions of one provider are two rules. Used for subtest names.
func ruleKey(rule rules.Rule) string {
	return fmt.Sprintf("%s/%d", rule.Type, rule.Version)
}

// detectorKey identifies a detector the same way the engine does: by type, plus
// a version for the detectors that have several implementations of the same
// type living side by side.
//
// The builtin package has its own copy of this, unexported. Repeating it here
// costs six lines and keeps the identity the engine uses out of that package's
// public surface, which is the right trade: nothing outside tests needs it.
type detectorKey struct {
	detectorType detector_typepb.DetectorType
	version      int
}

// keyFor derives a detector's identity. A detector that does not declare a
// version is treated as version zero, which is what the engine assumes too.
func keyFor(d detectors.Detector) detectorKey {
	key := detectorKey{detectorType: d.Type()}
	if versioned, ok := d.(detectors.Versioner); ok {
		key.version = versioned.Version()
	}
	return key
}

// byKey indexes detectors by that identity, so a rule can find the hand-written
// implementation it stands in for without this package importing the packages
// it is replacing.
func byKey(dets []detectors.Detector) map[detectorKey]detectors.Detector {
	out := make(map[detectorKey]detectors.Detector, len(dets))
	for _, d := range dets {
		out[keyFor(d)] = d
	}
	return out
}
