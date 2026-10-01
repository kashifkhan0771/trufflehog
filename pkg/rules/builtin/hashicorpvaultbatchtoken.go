package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// HashiCorpVaultBatchToken tokens (hvb.<50-300 chars>) are the second of two
// HashiCorp Vault token shapes a hand-written detector covers; the other is
// HashiCorpVaultToken. Both are verified the same way, against a server the
// token holder runs, which is why both need Endpoint.
var HashiCorpVaultBatchToken = rules.Rule{
	Type:     detector_typepb.DetectorType_HashiCorpVaultBatchToken,
	Keywords: []string{"hvb."},
	Description: "This detector detects and verifies HashiCorp Vault batch tokens. Vault batch tokens can be " +
		"used to access and manage stored secrets and resources.",
	Patterns: []rules.Pattern{
		// hvb. identifies itself, so no Prefix is needed.
		{Name: "key", Regex: `\b(hvb\.[A-Za-z0-9_.-]{50,300})(?:[^A-Za-z0-9_.-]|\z)`},
	},
	FullSecretID: "{key}:{endpoint}",
	// See HashiCorpVaultToken: the hand-written detector embeds
	// DefaultMultiPartCredentialProvider for the endpoint it looks for
	// alongside the token, which this rule's own endpoint pattern handles
	// outside of Patterns, so it is matched here by hand instead.
	MaxChunkSpan: 1024,
	Endpoint: rules.EndpointConfig{
		Pattern: &rules.Pattern{
			Regex: `(https?://[^\s/]*\.hashicorp\.cloud(?::\d+)?)(?:/[^\s]*)?`,
		},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{
				"key": "hvb.8vkKQlENCzsdfF8j61yX-ZFsan2Cw7gFp6r7O425u85HFJ_EJ4jKEIQOkrtDXtBi10Q71hA1XcW9aTMX1C_CI3_dXRZv7qdYdk2r7xgHWPB6PRWJ1Gk8cgSCifdFzctEq8oB7GVvouNndNWYzjFnMpfS2ViRb1_n3U6t3wI973IPFlJ5F7WRd-Px_BTHRJJbykE0_E8_",
				// Same fake HCP address HashiCorpVaultToken uses - see the
				// comment there for why they must match.
				"endpoint": "https://my-vault-cluster.z1.hashicorp.cloud:8200",
			},
			NotExamples: map[string][]string{
				"key": {
					// 49 characters: one short of the 50-300 a batch token needs.
					"hvb.5clLCZFNV8S2QT6INGDpyOpxyB9JKmyLDUwMbqJfgLq_nbK89",
				},
			},
		},
		// See HashiCorpVaultToken: no stored field exists for a revoked
		// token, so there is nothing for Integration.Invalid to name.
	},
	Verify: rules.HTTP{
		URL:           "/v1/auth/token/lookup-self",
		Headers:       map[string]string{"X-Vault-Token": "{key}"},
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401, 403},
	},
}
