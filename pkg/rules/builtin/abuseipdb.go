package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// AbuseIPDB API keys. The check endpoint returns 200 for some non-credential
// errors, so a live key is only confirmed when the response body carries the
// expected payload.
var AbuseIPDB = rules.Rule{
	Type:     detector_typepb.DetectorType_AbuseIPDB,
	Keywords: []string{"abuseipdb"},
	Description: "AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and " +
		"abusive activity on the internet. AbuseIPDB API keys can be used to report and check IP addresses " +
		"for abusive activities.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([a-z0-9]{80})\b`, Prefix: []string{"abuseipdb"}},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "4hh5344tfjgvq4k7bn7xj8b7tfq7xkwo886vompzom75wbbr4qmw2wxfogo4mvn4a4wfhym4l1vfz3zf"},
			NotExamples: map[string][]string{"key": {"kkibj3j4wj99ibag7i1mnbqns6puq80idw3706i8j76b2lajlj4h9du7794g9dpmrcg629be2u66mr2"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors1",
			Valid:   []string{"ABUSEIPDB"},
			Invalid: []string{"ABUSEIPDB_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:               "https://api.abuseipdb.com/api/v2/check",
		Query:             map[string]string{"ipAddress": "8.8.8.8"},
		Headers:           map[string]string{"Key": "{key}"},
		ValidStatus:       rules.StatusCodes{200},
		InvalidStatus:     rules.StatusCodes{401},
		ValidBodyContains: "ipAddress",
	},
}
