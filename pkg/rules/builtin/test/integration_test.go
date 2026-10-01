//go:build detectors
// +build detectors

// What the provider says about a real credential, run from each rule's
// Test.Integration.
//
// One live test covering every rule, replacing a hand-written integration file
// per detector: the only thing that differed between them was which stored
// secret to fetch, and that is now part of the rule.

package test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules/builtin"
)

// TestIntegrationVerification checks each rule against the provider itself: a
// working credential must come back verified, and a revoked one must come back
// definitively rejected rather than merely unconfirmed.
//
// The revoked half is the one worth having. A verifier pointed at the wrong URL,
// or reading the wrong status code, still reports a live credential as live; it
// is the revoked credential that shows whether the rule is really asking the
// provider anything.
func TestIntegrationVerification(t *testing.T) {
	for _, rule := range builtin.All {
		if rule.Disabled || rule.Test.Integration.Group == "" {
			continue
		}
		t.Run(rule.Type.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			stored, err := common.GetSecret(ctx, "trufflehog-testing", rule.Test.Integration.Group)
			if err != nil {
				t.Fatalf("could not read test secrets: %s", err)
			}
			detector := rules.New(rule, nil)

			t.Run("valid", func(t *testing.T) {
				results := verify(ctx, t, detector, rule, stored, rule.Test.Integration.Valid)
				if !anyVerified(results) {
					t.Errorf("a working credential was not verified: %s", whyNot(results))
				}
			})

			t.Run("revoked", func(t *testing.T) {
				results := verify(ctx, t, detector, rule, stored, rule.Test.Integration.Invalid)
				if anyVerified(results) {
					t.Error("a revoked credential was reported as verified")
				}
				// An error here means the attempt failed, not that the
				// provider said no, so the result proves nothing either way.
				for _, r := range results {
					if r.VerificationError() != nil {
						t.Errorf("verification did not complete: %v", r.VerificationError())
					}
				}
			})
		})
	}
}

// verify pastes the stored values into a piece of text the rule can read, then
// scans it with verification turned on.
func verify(ctx context.Context, t *testing.T, detector detectors.Detector, rule rules.Rule, stored *common.Secret, fields []string) []detectors.Result {
	t.Helper()
	if len(fields) == 0 {
		t.Skip("no credential fields declared")
	}

	// Each value gets a keyword in front of it, since most patterns will not
	// look further back than that for one.
	keyword := ""
	if len(rule.Keywords) > 0 {
		keyword = rule.Keywords[0]
	}
	var text strings.Builder
	for _, field := range fields {
		text.WriteString(keyword + " " + stored.MustGetField(field) + "\n")
	}

	results, err := detector.FromData(ctx, true, []byte(text.String()))
	if err != nil {
		t.Fatalf("scanning: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("the patterns found nothing in the stored credential")
	}
	return results
}

func anyVerified(results []detectors.Result) bool {
	for _, r := range results {
		if r.Verified {
			return true
		}
	}
	return false
}

// whyNot gathers the verification errors, which is the useful part of a failure
// here: a rule pointed at a dead endpoint and a genuinely revoked credential
// look the same without them.
func whyNot(results []detectors.Result) string {
	var reasons []string
	for _, r := range results {
		if err := r.VerificationError(); err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if len(reasons) == 0 {
		return "no verification error was reported"
	}
	return strings.Join(reasons, "; ")
}
