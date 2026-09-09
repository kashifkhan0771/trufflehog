package defs

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rules"
)

// ExampleSendGrid runs a rule end to end the way the engine does: detection
// against a chunk of scanned data, then verification against the provider. The
// provider is stubbed here so the example does not need a live credential.
func ExampleSendGrid() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer SG.aaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"scopes":["mail.send"]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	rule := SendGrid
	verify := rule.Verify.(rules.HTTP)
	verify.URL = srv.URL
	rule.Verify = verify

	detector := rules.New(rule, srv.Client())

	chunk := []byte(`SENDGRID_API_KEY = "SG.aaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`)
	results, err := detector.FromData(context.Background(), true, chunk)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	for _, r := range results {
		fmt.Printf("verified=%v raw=%s scopes=%s\n", r.Verified, r.Raw, r.ExtraData["scopes"])
	}
	// Output:
	// verified=true raw=SG.aaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb scopes=mail.send
}
