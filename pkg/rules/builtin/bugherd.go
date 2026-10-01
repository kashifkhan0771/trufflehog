package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Bugherd API keys. The key is sent as the basic auth username with a throwaway
// password, which is how the provider expects a key-only credential.
var Bugherd = rules.Rule{
	Type:     detector_typepb.DetectorType_Bugherd,
	Keywords: []string{"bugherd"},
	Description: "Bugherd is a visual feedback and bug tracking tool for websites. Bugherd API keys can be " +
		"used to access and manage projects, tasks, and feedback data.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([0-9a-z]{22})\b`, Prefix: []string{"bugherd"}},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "47p9pb0tdbm50fqo1xo5cv"},
			NotExamples: map[string][]string{"key": {"0xzmas6en5mtmo3oqsg5l", "o50djzdnbj0ddlz2uhfkvml"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors2",
			Valid:   []string{"BUGHERD"},
			Invalid: []string{"BUGHERD_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:           "https://www.bugherd.com/api_v2/projects.json",
		BasicUser:     "{key}",
		BasicPass:     "x",
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
	},
}
