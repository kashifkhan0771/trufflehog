// Package defs holds detectors declared as rules, using the runtime in
// pkg/detectors/rules.
//
// Each rule is the equivalent of a hand-written detector package: the same
// keywords, the same patterns, and the same verification behaviour. Replace
// swaps the hand-written implementations out for these, keyed on detector type
// and version.
package defs

import (
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/rules"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// SendGrid API keys. A 403 means the key is live but lacks the scope for the
// endpoint queried, which is still proof the key works. The rotation guide is
// only attached once the key is confirmed live.
var SendGrid = rules.Rule{
	Type:     detector_typepb.DetectorType_SendGrid,
	Keywords: []string{"SG."},
	Description: "SendGrid is a cloud-based service that provides email delivery and marketing campaigns. " +
		"SendGrid API keys can be used to send emails and manage other email-related tasks.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(`\bSG\.[\w\-]{20,24}\.[\w\-]{39,50}\b`)},
	},
	Verify: rules.HTTP{
		URL: "https://api.sendgrid.com/v3/scopes",
		Headers: map[string]string{
			"Authorization": "Bearer {key}",
			"Content-Type":  "application/json",
		},
		Valid:          rules.Status{200, 403},
		Invalid:        rules.Status{401},
		ValidExtraData: map[string]string{"rotation_guide": "https://howtorotate.com/docs/tutorials/sendgrid/"},
		Extract:        map[string]rules.Extract{"scopes": {JSONField: "scopes", Join: ","}},
	},
}

// Stripe live secret and restricted keys. Test keys ("sk_test") are
// deliberately not matched. A 403 indicates a restricted key without access to
// the charges endpoint, which still confirms the key is live.
var Stripe = rules.Rule{
	Type:     detector_typepb.DetectorType_Stripe,
	Keywords: []string{"k_live"},
	Description: "Stripe is a payment processing platform. Stripe API keys can be used to interact with " +
		"Stripe's services for processing payments, managing subscriptions, and more.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(`[rs]k_live_[a-zA-Z0-9]{20,247}`)},
	},
	ExtraData: map[string]string{"rotation_guide": "https://howtorotate.com/docs/tutorials/stripe/"},
	Verify: rules.HTTP{
		URL: "https://api.stripe.com/v1/charges",
		Headers: map[string]string{
			"Authorization": "Bearer {key}",
			"Content-Type":  "application/json",
		},
		Valid:   rules.Status{200, 403},
		Invalid: rules.Status{401},
	},
}

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
		{Name: "key", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"abuseipdb"}) + `\b([a-z0-9]{80})\b`)},
	},
	Verify: rules.HTTP{
		URL:               "https://api.abuseipdb.com/api/v2/check",
		Query:             map[string]string{"ipAddress": "8.8.8.8"},
		Headers:           map[string]string{"Key": "{key}"},
		Valid:             rules.Status{200},
		Invalid:           rules.Status{401},
		ValidBodyContains: "ipAddress",
	},
}

// Aylien application credentials, which are an ID and key pair that must be
// verified together. The two halves are often declared on separate lines, so
// the scan window is widened to keep them in the same chunk.
var Aylien = rules.Rule{
	Type:     detector_typepb.DetectorType_Aylien,
	Keywords: []string{"aylien"},
	Description: "Aylien is a text analysis platform that provides natural language processing and machine " +
		"learning APIs. Aylien API keys can be used to access and analyze text data.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"aylien"}) + `\b([a-z0-9]{32})\b`)},
		{Name: "id", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"aylien"}) + `\b([a-z0-9]{8})\b`)},
	},
	Raw:               "{key}",
	RawV2:             "{key}{id}",
	MaxCredentialSpan: 1024,
	Verify: rules.HTTP{
		URL: "https://api.aylien.com/news/stories",
		Headers: map[string]string{
			"X-AYLIEN-NewsAPI-Application-ID":  "{id}",
			"X-AYLIEN-NewsAPI-Application-Key": "{key}",
		},
		Valid:   rules.Status{200},
		Invalid: rules.Status{401},
	},
}

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
// belongs to is recorded once the credential is confirmed.
var GoDaddyOTE = rules.Rule{
	Type:        detector_typepb.DetectorType_GoDaddy,
	Version:     1,
	Keywords:    []string{"godaddy"},
	Description: goDaddyDescription,
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "_", 37))},
		{Name: "secret", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "", 22))},
	},
	Raw: "{key}",
	// No RawV2 on purpose. The secret pattern is a bare 22-character run, so a
	// file holding one real key next to any similar-looking strings would pair
	// the key with each of them. Deduplicating on the key alone reports the
	// exposed key once, however many candidate secrets sit near it.
	//
	// Present but empty until verification names the environment.
	ExtraData: map[string]string{},
	Verify: rules.HTTP{
		URL:            "https://api.ote-godaddy.com/v1/domains/available",
		Query:          map[string]string{"domain": "example.com"},
		Headers:        map[string]string{"Authorization": "sso-key {key}:{secret}"},
		Valid:          rules.Status{200, 403},
		Invalid:        rules.Status{401},
		ValidExtraData: map[string]string{"Environment": "OTE"},
	},
}

// GoDaddyProd is the production counterpart of GoDaddyOTE, with a shorter key.
var GoDaddyProd = rules.Rule{
	Type:        detector_typepb.DetectorType_GoDaddy,
	Version:     2,
	Keywords:    []string{"godaddy"},
	Description: goDaddyDescription,
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "_", 35))},
		{Name: "secret", Regex: regexp.MustCompile(detectors.PrefixRegex([]string{"godaddy"}) + common.BuildRegex("a-zA-Z0-9", "", 22))},
	},
	Raw: "{key}",
	// No RawV2 on purpose. The secret pattern is a bare 22-character run, so a
	// file holding one real key next to any similar-looking strings would pair
	// the key with each of them. Deduplicating on the key alone reports the
	// exposed key once, however many candidate secrets sit near it.
	//
	// Present but empty until verification names the environment.
	ExtraData: map[string]string{},
	Verify: rules.HTTP{
		URL:            "https://api.godaddy.com/v1/domains/available",
		Query:          map[string]string{"domain": "example.com"},
		Headers:        map[string]string{"Authorization": "sso-key {key}:{secret}"},
		Valid:          rules.Status{200, 403},
		Invalid:        rules.Status{401},
		ValidExtraData: map[string]string{"Environment": "Prod"},
	},
}

const goDaddyDescription = "GoDaddy offers website building, hosting and security tools and services to construct, expand and protect the online presence." +
	"GoDaddy provides applications and access to relevant third-party products and platforms to connect their customers"

// LaunchDarkly tokens are UUIDs behind an api- or sdk- prefix. Client-side
// mob- keys are deliberately not matched, because they are meant to be public.
//
// The token is sent as the Authorization header on its own, with no scheme
// prefix. A successful response describes the token, and those details are
// pulled out so a finding says which account and project it opens.
var LaunchDarkly = rules.Rule{
	Type:     detector_typepb.DetectorType_LaunchDarkly,
	Keywords: []string{"api-", "sdk-"},
	Description: "LaunchDarkly is a feature management platform that allows teams to control the visibility of " +
		"features to users. LaunchDarkly API keys can be used to access and modify feature flags and other " +
		"resources within a LaunchDarkly account.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: regexp.MustCompile(`\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`)},
	},
	// Present but empty until verification describes the token.
	ExtraData: map[string]string{},
	Verify: rules.HTTP{
		URL:     "https://app.launchdarkly.com/api/v2/caller-identity",
		Headers: map[string]string{"Authorization": "{key}"},
		Valid:   rules.Status{200},
		Invalid: rules.Status{401},
		Extract: map[string]rules.Extract{
			"account":          {JSONField: "accountId"},
			"environment_id":   {JSONField: "environmentId"},
			"project_id":       {JSONField: "projectId"},
			"environment_name": {JSONField: "environmentName"},
			"project_name":     {JSONField: "projectName"},
			"auth_kind":        {JSONField: "authKind"},
			"token_kind":       {JSONField: "tokenKind"},
			"client_id":        {JSONField: "clientId"},
			"token_name":       {JSONField: "tokenName"},
			"member_id":        {JSONField: "memberId"},
		},
	},
}

// All is every rule declared in this package.
var All = []rules.Rule{SendGrid, Stripe, AbuseIPDB, Aylien, GoDaddyOTE, GoDaddyProd, LaunchDarkly}

// detectorKey identifies a detector the same way the engine does: by type,
// plus a version for the detectors that have several implementations of the
// same type living side by side.
type detectorKey struct {
	detectorType detector_typepb.DetectorType
	version      int
}

// keyFor derives a detector's identity. A detector that does not declare a
// version is treated as version zero, which is what the engine assumes too.
func keyFor(d detectors.Detector) detectorKey {
	key := detectorKey{detectorType: d.Type()}
	if versioned, ok := d.(detectors.Versioner); ok {
		key.version = versioned.Version()
	}
	return key
}

// Replace returns dets with every detector that has an equivalent rule in this
// package swapped for the rule-backed implementation. Detectors without a rule
// are returned untouched, and order is preserved.
//
// Verification requests use client, or the standard detector HTTP client when
// client is nil.
//
// Substituting rather than appending is deliberate: the engine keys detectors
// on type and version, so registering both implementations would leave which
// one runs down to map ordering.
func Replace(existing []detectors.Detector, client *http.Client) []detectors.Detector {
	// Build each rule once up front, then look them up by identity, so the
	// cost does not depend on how many detectors are being scanned through.
	ruleDetectors := make(map[detectorKey]detectors.Detector, len(All))
	for _, rule := range All {
		detector := rules.New(rule, client)
		ruleDetectors[keyFor(detector)] = detector
	}

	// Rebuild the list rather than writing into the caller's slice, which may
	// be shared, and keep every position so nothing else that indexes into it
	// is disturbed.
	swapped := make([]detectors.Detector, len(existing))
	for i, detector := range existing {
		if replacement, ok := ruleDetectors[keyFor(detector)]; ok {
			swapped[i] = replacement
			continue
		}
		swapped[i] = detector
	}
	return swapped
}

// Detectors builds a detector for every rule in All, for callers that want to
// run only the rule-backed detectors rather than substitute them into an
// existing list.
func Detectors(client *http.Client) []detectors.Detector {
	built := make([]detectors.Detector, 0, len(All))
	for _, rule := range All {
		built = append(built, rules.New(rule, client))
	}
	return built
}
