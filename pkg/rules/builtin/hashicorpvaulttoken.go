package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// HashiCorpVaultToken tokens (periodic, service, and admin) authenticate
// against a Vault server the token holder runs - HashiCorp has no hosted
// endpoint of its own to try, so a token is only verifiable against an
// address the scanned data mentions or an operator configures. That is what
// Endpoint is for: without it there would be nowhere to send the request.
var HashiCorpVaultToken = rules.Rule{
	Type: detector_typepb.DetectorType_HashiCorpVaultToken,
	// "s." alone would match almost anything, which is why "vault" carries
	// the keyword instead - copied from the hand-written detector this
	// replaces.
	Keywords: []string{"hvs.", "vault"},
	Description: "HashiCorp Vault is a secrets management service. Vault tokens (periodic, service, and admin) " +
		"can be used to access and manage stored secrets and resources.",
	Patterns: []rules.Pattern{
		// hvs. (newer, service) and s. (legacy) tokens identify themselves,
		// so neither needs a Prefix.
		{Name: "key", Regex: `\b(hvs\.[A-Za-z0-9_-]{90,120}|s\.[A-Za-z0-9_-]{18,40})(?:$|[^A-Za-z0-9_-])`},
	},
	FullSecretID: "{key}:{endpoint}",
	// The hand-written detector embeds DefaultMultiPartCredentialProvider
	// even though it has one required pattern, since the endpoint it looks
	// for alongside the token is itself an optional second part. This rule's
	// own endpoint pattern is handled separately from Patterns, so it would
	// otherwise fall into the one-pattern default - matched here by hand.
	MaxChunkSpan: 1024,
	Endpoint: rules.EndpointConfig{
		// HCP Vault addresses are the only ones recognisable on sight;
		// anything self-hosted elsewhere can only reach this rule through a
		// configured endpoint.
		Pattern: &rules.Pattern{
			Regex: `(https?://[^\s/]*\.hashicorp\.cloud(?::\d+)?)(?:/[^\s]*)?`,
		},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{
				"key": "hvs.odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPhDeOZIiBOB-Y6sHrFH2ZUCr-lgotu2iX",
				// Shared with HashiCorpVaultBatchToken's own endpoint
				// example on purpose: TestDetectionWithEveryOtherCredential
				// scans one document holding every rule's examples, and
				// this rule's endpoint pattern has no way to tell the two
				// providers' HCP addresses apart. Using the same fake value
				// means finding either one still matches what this rule
				// expects.
				"endpoint": "https://my-vault-cluster.z1.hashicorp.cloud:8200",
			},
			NotExamples: map[string][]string{
				"key": {
					// 89 characters: one short of the 90-120 a service token needs.
					"hvs.W7GboIRoL3u6aHwnMztVuaP_coUNEhEkk_iqq8vH2BzNZV45pFCiRcDCajhDieQjEJ_Bq8F80ymm3T207gmhZRnFy",
					// 17 characters: one short of the 18-40 a legacy token needs.
					"s.dyZQJiJSZQdoHwHen",
				},
			},
		},
		// No stored field exists for a revoked HashiCorp Vault token - the
		// hand-written detector's own integration test checks revocation
		// with a hardcoded fake token rather than one from the secret
		// store, so there is nothing here for Integration.Invalid to name.
	},
	Verify: rules.HTTP{
		// A path, not a full URL: Endpoint is configured, so this is
		// joined onto whichever address is being tried.
		URL:           "/v1/auth/token/lookup-self",
		Headers:       map[string]string{"X-Vault-Token": "{key}"},
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401, 403},
	},
}
