package defs

import (
	"context"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// chunkAround buries a secret in roughly four kilobytes of ordinary source, so
// the benchmark measures the same shape of work a real scan does rather than
// regex matching against a bare token.
func chunkAround(secret string) []byte {
	var b strings.Builder
	b.WriteString(strings.Repeat("// an ordinary line of source that holds no credential\n", 40))
	b.WriteString(secret)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("func doSomething() error { return nil }\n", 40))
	return []byte(b.String())
}

func benchmarkDetector(b *testing.B, d detectors.Detector, data []byte) {
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		if _, err := d.FromData(ctx, false, data); err != nil {
			b.Fatal(err)
		}
	}
}

// Each pair runs the hand-written detector and its rule over identical input.
// The "Miss" variants matter most: a chunk whose keyword matched but which
// holds no credential is the common case during a real scan.
func BenchmarkDetectors(b *testing.B) {
	hit := map[string][]byte{
		"sendgrid":  chunkAround(`SENDGRID = "SG.ZV-VYwtHzJJW4wF8yPQk3.ZXg9c9DZuOgUcW1f2inP6SqfEsYG82zAe0wG7brZZ5OvruV-I"`),
		"stripe":    chunkAround(`STRIPE = "rk_live_HUOlkIKhNEYOPS0oDSwGwJHbg4xGaXNeJZ2CdvDGeVZQHljoq5TuFwQHgME3W"`),
		"abuseipdb": chunkAround(`abuseipdb key = o8oqti3tghu2xic76ii4t7jb9bxuzd4200j1yrkdjl6s8834hx4dgz1wwo90diqraakjd13sljcjkfnf`),
		"aylien":    chunkAround("aylien key: cr479du2l9pkmhar8gw5hufofvwp86q9\naylien id: y3ejw028"),
		"godaddy-ote": chunkAround("godaddy key: u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dK\n" +
			"godaddy secret: IBXuDL7DxtpYlSXpfKtHF4"),
		"launchdarkly": chunkAround(`LD = "api-1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"`),
	}
	miss := map[string][]byte{
		"sendgrid":     chunkAround("sendgrid is configured elsewhere"),
		"stripe":       chunkAround("no k_live token in this file"),
		"abuseipdb":    chunkAround("abuseipdb is mentioned but no key follows"),
		"aylien":       chunkAround("aylien is mentioned but no credential follows"),
		"godaddy-ote":  chunkAround("godaddy is mentioned but no credential follows"),
		"launchdarkly": chunkAround("api- and sdk- appear but no token follows"),
	}

	for _, tc := range replacements {
		hitData, ok := hit[tc.name]
		if !ok {
			continue
		}
		ruleDetector := rules.New(tc.rule, nil)

		b.Run(tc.name+"/hit/handwritten", func(b *testing.B) { benchmarkDetector(b, tc.goDetector, hitData) })
		b.Run(tc.name+"/hit/rule", func(b *testing.B) { benchmarkDetector(b, ruleDetector, hitData) })
		b.Run(tc.name+"/miss/handwritten", func(b *testing.B) { benchmarkDetector(b, tc.goDetector, miss[tc.name]) })
		b.Run(tc.name+"/miss/rule", func(b *testing.B) { benchmarkDetector(b, ruleDetector, miss[tc.name]) })
	}
}

// BenchmarkBuildDetectorList measures the startup cost of assembling the full
// detector list, with and without the substitution, since every rule is
// constructed and validated at that point.
func BenchmarkBuildDetectorList(b *testing.B) {
	b.Run("handwritten", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_ = defaults.DefaultDetectors()
		}
	})
	b.Run("with-rules", func(b *testing.B) {
		base := defaults.DefaultDetectors()
		b.ResetTimer()
		b.ReportAllocs()
		for range b.N {
			_ = Replace(base, nil)
		}
	})
}
