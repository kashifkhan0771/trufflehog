// Package builtin holds the detectors that ship as rules, built on the runtime
// in the parent package.
//
// Each rule is the equivalent of a hand-written detector package: the same
// keywords, the same patterns, and the same verification behaviour. Replace
// swaps the hand-written implementations out for these, keyed on detector type
// and version.
//
// Every detector lives in its own file named after it, so godaddy.go holds the
// GoDaddy rules and nothing else. This file holds only the parts they share:
// the list of them, and the code that turns them into detectors the engine can
// run. Adding a detector means adding its file and adding its name to All.
package builtin

import (
	"net/http"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// All is every rule declared in this package.
//
// It is written out by hand rather than collected automatically, so that one
// place shows every detector this package provides. A rule missing from here
// is not registered anywhere, which the tests check for.
var All = []rules.Rule{
	AbuseIPDB,
	AmplitudeApiKey,
	Appcues,
	Aylien,
	Beebole,
	Borgbase,
	Bugherd,
	Bulksms,
	Dropbox,
	EndorLabs,
	GoDaddyOTE,
	GoDaddyProd,
	HashiCorpVaultBatchToken,
	HashiCorpVaultToken,
	LaunchDarkly,
	SendGrid,
	Stripe,
}

// detectorKey identifies a detector the same way the engine does: by type,
// plus a version for the detectors that have several implementations of the
// same type living side by side.
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

// Replace returns existing with every detector that has an equivalent rule in
// this package swapped for the rule-backed implementation. Detectors without a
// rule are returned untouched, and order is preserved.
//
// A rule marked Disabled removes its detector from the list instead. Nothing
// then scans for that provider, so the returned slice can be shorter than the
// one passed in.
//
// Verification requests use client, or the standard detector HTTP client when
// client is nil.
//
// Substituting rather than appending is deliberate: the engine keys detectors
// on type and version, so registering both implementations would leave which
// one runs down to map ordering.
func Replace(existing []detectors.Detector, client *http.Client) []detectors.Detector {
	// Build each rule once up front, then look them up by identity, so the
	// cost does not depend on how many detectors are being scanned through.
	// Disabled rules are built too, so an invalid one is still caught.
	ruleDetectors := make(map[detectorKey]detectors.Detector, len(All))
	disabled := make(map[detectorKey]bool)
	for _, rule := range All {
		detector := rules.New(rule, client)
		if rule.Disabled {
			disabled[keyFor(detector)] = true
			continue
		}
		ruleDetectors[keyFor(detector)] = detector
	}

	// Rebuild the list rather than writing into the caller's slice, which may
	// be shared, and keep the order so nothing else reading it is disturbed.
	swapped := make([]detectors.Detector, 0, len(existing))
	for _, detector := range existing {
		key := keyFor(detector)
		if disabled[key] {
			continue
		}
		if replacement, ok := ruleDetectors[key]; ok {
			swapped = append(swapped, replacement)
			continue
		}
		swapped = append(swapped, detector)
	}
	return swapped
}

// Detectors builds a detector for every enabled rule in All, for callers that
// want to run only the rule-backed detectors rather than substitute them into
// an existing list.
func Detectors(client *http.Client) []detectors.Detector {
	built := make([]detectors.Detector, 0, len(All))
	for _, rule := range All {
		if rule.Disabled {
			continue
		}
		built = append(built, rules.New(rule, client))
	}
	return built
}
