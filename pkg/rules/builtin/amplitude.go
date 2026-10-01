package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Amplitude API keys, which are a key and secret pair used as basic auth.
//
// The two halves look identical, both being 32 hex characters, so the same
// string would otherwise fill both slots.
var AmplitudeApiKey = rules.Rule{
	Type:     detector_typepb.DetectorType_AmplitudeApiKey,
	Keywords: []string{"amplitude"},
	Description: "Amplitude is a product analytics service that helps companies track and analyze user " +
		"behavior within web and mobile applications. Amplitude API keys can be used to access and modify " +
		"this data.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([0-9a-f]{32})\b`, Prefix: []string{"amplitude"}},
		{Name: "secret", Regex: `\b([0-9a-f]{32})\b`, Prefix: []string{"amplitude"}},
	},
	SecretID:         "{key}",
	FullSecretID:     "{key}{secret}",
	DistinctCaptures: true,
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"key": "c7ce65426f74bde94fb78c8d5f08b79a", "secret": "ffd2b49c12a4b0062983475eb46c5296"},
			NotExamples: map[string][]string{
				"key":    {"f62e338d74ff1fe4f7f505aef9ebdd2"},
				"secret": {"f62e338d74ff1fe4f7f505aef9ebdd2"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors3",
			Valid:   []string{"AMPLITUDEAPI_KEY", "AMPLITUDEAPI_SECRET"},
			Invalid: []string{"AMPLITUDEAPI_KEY_INACTIVE", "AMPLITUDEAPI_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:           "https://amplitude.com/api/2/taxonomy/category",
		BasicUser:     "{key}",
		BasicPass:     "{secret}",
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401, 403},
	},
}
