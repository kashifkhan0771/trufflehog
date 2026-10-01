// Tests for running a rule against a chunk of scanned data: what it finds,
// and what it reports.

package rules

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

func TestFromDataCrossProduct(t *testing.T) {
	r := Rule{
		Type:        detector_typepb.DetectorType_SendGrid,
		Description: "multi-pattern test",
		Keywords:    []string{"multi_"},
		Patterns: []Pattern{
			{Name: "key", Regex: `multi_key_[a-z]{3}`},
			{Name: "id", Regex: `multi_id_[a-z]{3}`},
		},
		SecretID:     "{key}",
		FullSecretID: "{key}{id}",
		Verify:       None{},
	}
	detector := New(r, nil)

	// Two keys, one id: expect a 2x1 cross product, each de-duplicated.
	data := "multi_key_abc multi_key_abc multi_key_def multi_id_xyz"
	results, err := detector.FromData(context.Background(), false, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (2 keys x 1 id)", len(results))
	}
	for _, result := range results {
		if result.SecretParts["id"] != "multi_id_xyz" {
			t.Errorf("SecretParts[id] = %q, want multi_id_xyz", result.SecretParts["id"])
		}
	}
}

func TestFromDataNoMatchReturnsNothing(t *testing.T) {
	detector := New(testRule(), nil)
	results, err := detector.FromData(context.Background(), false, []byte("nothing interesting here"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

// TestDistinctCapturesDropsSelfPairs covers the case the flag exists for: both
// halves of a credential are found by the same regex, so without it a lone
// value in the data is paired with itself and reported as a full credential.
func TestDistinctCapturesDropsSelfPairs(t *testing.T) {
	makeRule := func(distinct bool) Rule {
		return Rule{
			Type:        detector_typepb.DetectorType_SendGrid,
			Description: "same regex for both halves",
			Keywords:    []string{"pair_"},
			Patterns: []Pattern{
				{Name: "key", Regex: `pair_[a-z]{3}`},
				{Name: "secret", Regex: `pair_[a-z]{3}`},
			},
			SecretID:         "{key}",
			FullSecretID:     "{key}{secret}",
			DistinctCaptures: distinct,
			Verify:           None{},
		}
	}

	for _, tc := range []struct {
		name     string
		distinct bool
		data     string
		want     int
	}{
		// Two values give four pairs, two of which pair a value with itself.
		{"two values, kept", false, "pair_abc pair_def", 4},
		{"two values, dropped", true, "pair_abc pair_def", 2},
		// One value can only pair with itself, so nothing survives.
		{"one value, kept", false, "pair_abc", 1},
		{"one value, dropped", true, "pair_abc", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detector := New(makeRule(tc.distinct), nil)
			results, err := detector.FromData(context.Background(), false, []byte(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != tc.want {
				t.Fatalf("got %d results, want %d", len(results), tc.want)
			}
			if !tc.distinct {
				return
			}
			for _, result := range results {
				if result.SecretParts["key"] == result.SecretParts["secret"] {
					t.Errorf("a value was paired with itself: %q", result.SecretParts["key"])
				}
			}
		})
	}
}

// Every rule declares a chunk span, so the engine knows how much of the
// chunk to hand it without the rule having to ask. Which number it gets
// follows from the shape of the credential.
func TestChunkSpan(t *testing.T) {
	spanOf := func(t *testing.T, rule Rule) int64 {
		t.Helper()
		provider, ok := New(rule, nil).(detectors.MultiPartCredentialProvider)
		if !ok {
			t.Fatal("rule does not implement MultiPartCredentialProvider")
		}
		return provider.MaxCredentialSpan()
	}

	// The numbers are written out rather than compared against the constants
	// they come from, which would pass whatever those constants were changed
	// to. They are a decision about how much data a scan reads, so moving one
	// should mean editing this line too.
	const (
		wantSingle = 512
		wantMulti  = 1024
	)

	// One pattern: a token sits beside the word that introduces it.
	if got := spanOf(t, testRule()); got != wantSingle {
		t.Errorf("single pattern: span = %d, want %d", got, wantSingle)
	}

	// Two patterns: the halves can be pages apart in the same file.
	multi := testRule()
	multi.Patterns = append(multi.Patterns, Pattern{Name: "id", Regex: `id_[a-z]{6}`})
	multi.SecretID = "{key}"
	if got := spanOf(t, multi); got != wantMulti {
		t.Errorf("two patterns: span = %d, want %d", got, wantMulti)
	}

	// An explicit value wins over both.
	custom := testRule()
	custom.MaxChunkSpan = 4096
	if got := spanOf(t, custom); got != 4096 {
		t.Errorf("explicit span = %d, want 4096", got)
	}
}

// Version stays optional: a rule that declares none is a provider with one
// implementation, not version zero.
func TestVersionerIsOptional(t *testing.T) {
	if _, ok := New(testRule(), nil).(detectors.Versioner); ok {
		t.Error("plain rule must not implement Versioner")
	}

	versioned := testRule()
	versioned.Version = 2
	v, ok := New(versioned, nil).(detectors.Versioner)
	if !ok {
		t.Fatal("versioned rule must implement Versioner")
	}
	if v.Version() != 2 {
		t.Errorf("version = %d, want 2", v.Version())
	}
}

// TestMinEntropyDropsOrderlyValues covers the entropy floor. A repeated run of
// one character is the shape of a placeholder or a filler string, not a key.
func TestMinEntropyDropsOrderlyValues(t *testing.T) {
	const random = "tk_x7q2mv9bpe"
	const orderly = "tk_aaaaaaaaaa"

	rule := testRule()
	rule.Verify = None{}
	rule.Test = Test{Detection: DetectionTest{Examples: map[string]string{"key": random}}}

	// Without a floor both values look like credentials.
	results, err := New(rule, nil).FromData(context.Background(), false, []byte(orderly+" "+random))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected both values without an entropy floor, got %d", len(results))
	}

	// With one, only the random-looking value survives.
	rule.Patterns[0].MinEntropy = 3
	results, err = New(rule, nil).FromData(context.Background(), false, []byte(orderly+" "+random))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected the orderly value to be dropped, got %d results", len(results))
	}
	if got := string(results[0].Raw); got != random {
		t.Errorf("the wrong value survived: %q", got)
	}
}
