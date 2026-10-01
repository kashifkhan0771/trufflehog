package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Aylien application credentials, which are an ID and key pair that must be
// verified together.
var Aylien = rules.Rule{
	Type:     detector_typepb.DetectorType_Aylien,
	Keywords: []string{"aylien"},
	Description: "Aylien is a text analysis platform that provides natural language processing and machine " +
		"learning APIs. Aylien API keys can be used to access and analyze text data.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([a-z0-9]{32})\b`, Prefix: []string{"aylien"}},
		{Name: "id", Regex: `\b([a-z0-9]{8})\b`, Prefix: []string{"aylien"}},
	},
	SecretID:     "{key}",
	FullSecretID: "{key}{id}",
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"key": "6846p7q9m2i0hz2uep1enthjxjqi3ogz", "id": "rclri1qz"},
			NotExamples: map[string][]string{
				"key": {"5kok16zv0mwufxbv932byv7s6ehogfq"},
				"id":  {"j865ufr"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors1",
			Valid:   []string{"AYLIEN", "AYLIEN_ID"},
			Invalid: []string{"AYLIEN_INACTIVE", "AYLIEN_ID"},
		},
	},
	Verify: rules.HTTP{
		URL: "https://api.aylien.com/news/stories",
		Headers: map[string]string{
			"X-AYLIEN-NewsAPI-Application-ID":  "{id}",
			"X-AYLIEN-NewsAPI-Application-Key": "{key}",
		},
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
	},
}
