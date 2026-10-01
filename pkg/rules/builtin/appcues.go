package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Appcues credentials, which are three separate values: an account ID that
// selects which account to query, and a username and key used as basic auth.
//
// The account ID goes into the URL path rather than a header, so this is the
// one rule so far whose endpoint is built from captured data. The runtime
// escapes it into the path, so a value can add nothing to the address beyond
// the one segment it fills.
var Appcues = rules.Rule{
	Type:     detector_typepb.DetectorType_Appcues,
	Keywords: []string{"appcues"},
	Description: "Appcues is a user engagement platform that helps create personalized user experiences. " +
		"The detected credentials can be used to access and manage user engagement flows and data.",
	// All three values go into SecretParts. The hand-written detector this
	// replaces left the account id out, which analyzers and secret storage read;
	// the identity fields are unchanged.
	Patterns: []rules.Pattern{
		{Name: "id", Regex: `\b([0-9]{5})\b`, Prefix: []string{"appcues"}},
		{Name: "username", Regex: `\b([a-z0-9-]{39})\b`, Prefix: []string{"appcues"}},
		{Name: "key", Regex: `\b([a-z0-9-]{36})\b`, Prefix: []string{"appcues"}},
	},
	SecretID: "{key}",
	// The account ID is deliberately left out of FullSecretID, matching the
	// detector this replaces: the same key and username against a different
	// account is the same exposed credential.
	FullSecretID: "{key}{username}",
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"id": "40318", "username": "xntq186kyo3i8cwu7j29uk32qoiv3p6mrtjjpu7", "key": "1-0oolh31uqg0pzkq143b07luay5gcq8nkm7"},
			NotExamples: map[string][]string{
				"id":       {"4031"},
				"username": {"wkpumqgkgmyjjtt1rmggrny3caz1o6s3bjqzap"},
				"key":      {"wg-38n46bx7v03nlz6hwdqryzdae00wqgot"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors1",
			Valid:   []string{"APPCUES", "APPCUES_ID", "APPCUES_USER"},
			Invalid: []string{"APPCUES_INACTIVE", "APPCUES_ID", "APPCUES_USER"},
		},
	},
	Verify: rules.HTTP{
		URL:           "https://api.appcues.com/v2/accounts/{id}/flows",
		BasicUser:     "{username}",
		BasicPass:     "{key}",
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401, 403, 400},
	},
}
