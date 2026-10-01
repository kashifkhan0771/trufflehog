package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Beebole API keys. The listing endpoint is a POST that takes the operation in
// a JSON body, so the request carries a fixed body alongside the credential.
var Beebole = rules.Rule{
	Type:     detector_typepb.DetectorType_Beebole,
	Keywords: []string{"beebole"},
	Description: "Beebole is a time tracking and business management tool. Beebole API keys can be used to " +
		"access and manage time tracking data and other business-related information.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([0-9a-z]{40})\b`, Prefix: []string{"beebole"}},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "dl1erbfqfoeqh3av90ric7phkqdlmtt7ns26lrwb"},
			NotExamples: map[string][]string{"key": {"qcab69m64p2g158z6tnovmizwdiaeq1kdfy6sps"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors2",
			Valid:   []string{"BEEBOLE"},
			Invalid: []string{"BEEBOLE_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		Method:        "POST",
		URL:           "https://beebole-apps.com/api/v2",
		Headers:       map[string]string{"Content-Type": "application/json"},
		Body:          map[string]string{"service": "custom_field.list"},
		BasicUser:     "{key}",
		BasicPass:     "x",
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
	},
}
