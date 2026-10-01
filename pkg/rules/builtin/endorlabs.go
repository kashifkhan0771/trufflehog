package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Endor Labs API keys, which come as a key and a secret sent together in a JSON
// body.
//
// Both halves are found by the same regex, so without DistinctCaptures a lone
// key in a file would be paired with itself and reported as a full credential.
var EndorLabs = rules.Rule{
	Type:     detector_typepb.DetectorType_EndorLabs,
	Keywords: []string{"endr+"},
	Description: "Endorlabs provides API keys that can be used to authenticate and interact with its " +
		"services. These keys should be kept confidential to prevent unauthorized access.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b(endr\+[a-zA-Z0-9-]{16})\b`},
		{Name: "secret", Regex: `\b(endr\+[a-zA-Z0-9-]{16})\b`},
	},
	SecretID:         "{key}",
	FullSecretID:     "{key}{secret}",
	DistinctCaptures: true,
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"key": "endr+MPLCM7HUFpk5acdI", "secret": "endr+bzlpkd6XgaNJQ8mj"},
			NotExamples: map[string][]string{
				"key":    {"endr+AmHMPGPPA0NlGte"},
				"secret": {"endr+AmHMPGPPA0NlGte"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors5",
			Valid:   []string{"ENDOR_KEY", "ENDOR_SECRET"},
			Invalid: []string{"ENDOR_KEY_INACTIVE", "ENDOR_SECRET_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		Method:  "POST",
		URL:     "https://api.endorlabs.com/v1/auth/api-key",
		Headers: map[string]string{"Content-Type": "application/json"},
		// Safe to place directly in JSON: the pattern above admits only
		// letters, digits and dashes, so a captured value cannot close the
		// string or add a field.
		Body:          map[string]string{"key": "{key}", "secret": "{secret}"},
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
	},
}
