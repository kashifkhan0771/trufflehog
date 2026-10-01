package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// GoDaddyOTE matches credentials for GoDaddy's test environment.
//
// GoDaddy issues a key and a secret that are only meaningful together: the two
// are combined into a single "sso-key <key>:<secret>" authorization header. A
// 403 means the credential is real but not entitled to the endpoint queried,
// which still confirms it works.
//
// There are two GoDaddy rules because the two environments use different key
// lengths and a credential for one is not valid against the other. They share a
// detector type and are told apart by version, so the environment a finding
// belongs to is recorded once the credential is confirmed. Both live in this
// file because they are one provider described twice.
var GoDaddyOTE = rules.Rule{
	Type:        detector_typepb.DetectorType_GoDaddy,
	Version:     1,
	Keywords:    []string{"godaddy"},
	Description: goDaddyDescription,
	// Both halves go into SecretParts. The hand-written detector this replaces
	// reported only the key there, which left analyzers and secret storage
	// without the secret; the identity fields are unchanged.
	Patterns: []rules.Pattern{
		{Name: "key", Regex: common.BuildRegex("a-zA-Z0-9", "_", 37), Prefix: []string{"godaddy"}},
		{Name: "secret", Regex: common.BuildRegex("a-zA-Z0-9", "", 22), Prefix: []string{"godaddy"}},
	},
	SecretID: "{key}",
	// No FullSecretID on purpose. The secret pattern is a bare 22-character
	// run, so a file holding one real key next to any similar-looking strings
	// would pair the key with each of them. Deduplicating on the key alone reports the
	// exposed key once, however many candidate secrets sit near it.
	//
	// Present but empty until verification names the environment.
	ExtraData: map[string]string{},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"key": "tOd4UYETIay2BV6DfVPClogqoPchv5V7S82qT", "secret": "090I5Qe43W6T8ygpnnhcc8"},
			NotExamples: map[string][]string{
				"key":    {"drOJRBRY6H_qsP795nf4Gakq5p1Vm8kV6um4"},
				"secret": {"26ZWOf0WOOsEgigYWPnsu"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors5",
			Valid:   []string{"GODADDY_OTE"},
			Invalid: []string{"GODADDY_OTE_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:            "https://api.ote-godaddy.com/v1/domains/available",
		Query:          map[string]string{"domain": "example.com"},
		Headers:        map[string]string{"Authorization": "sso-key {key}:{secret}"},
		ValidStatus:    rules.StatusCodes{200, 403},
		InvalidStatus:  rules.StatusCodes{401},
		ValidExtraData: map[string]string{"Environment": "OTE"},
	},
}

// GoDaddyProd is the production counterpart of GoDaddyOTE, with a shorter key.
var GoDaddyProd = rules.Rule{
	Type:        detector_typepb.DetectorType_GoDaddy,
	Version:     2,
	Keywords:    []string{"godaddy"},
	Description: goDaddyDescription,
	// Both halves go into SecretParts, as for the OTE rule above.
	Patterns: []rules.Pattern{
		{Name: "key", Regex: common.BuildRegex("a-zA-Z0-9", "_", 35), Prefix: []string{"godaddy"}},
		{Name: "secret", Regex: common.BuildRegex("a-zA-Z0-9", "", 22), Prefix: []string{"godaddy"}},
	},
	SecretID: "{key}",
	// No FullSecretID on purpose. The secret pattern is a bare 22-character
	// run, so a file holding one real key next to any similar-looking strings would pair
	// the key with each of them. Deduplicating on the key alone reports the
	// exposed key once, however many candidate secrets sit near it.
	//
	// Present but empty until verification names the environment.
	ExtraData: map[string]string{},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"key": "yvMpy62O6S_Q1_IEE1HSa2bB9UoK4tYnzNL", "secret": "090I5Qe43W6T8ygpnnhcc8"},
			NotExamples: map[string][]string{
				"key":    {"eK6kjcbhgN7kw_jSbbciSPOcSeVce2LWxm"},
				"secret": {"26ZWOf0WOOsEgigYWPnsu"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors5",
			Valid:   []string{"GODADDY_PROD"},
			Invalid: []string{"GODADDY_PROD_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:            "https://api.godaddy.com/v1/domains/available",
		Query:          map[string]string{"domain": "example.com"},
		Headers:        map[string]string{"Authorization": "sso-key {key}:{secret}"},
		ValidStatus:    rules.StatusCodes{200, 403},
		InvalidStatus:  rules.StatusCodes{401},
		ValidExtraData: map[string]string{"Environment": "Prod"},
	},
}

const goDaddyDescription = "GoDaddy offers website building, hosting and security tools and services to construct, expand and protect the online presence." +
	"GoDaddy provides applications and access to relevant third-party products and platforms to connect their customers"
