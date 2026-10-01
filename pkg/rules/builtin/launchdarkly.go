package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

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
		{Name: "key", Regex: `\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`},
	},
	// Present but empty until verification describes the token.
	ExtraData: map[string]string{},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "sdk-v1qbwqsd-xu64-4sb0-b17g-w4d8nfsk1a7m"},
			NotExamples: map[string][]string{"key": {"sdk-sdaw5g5l-5w6q-5ksn-o5kh-f59guwgzzf1b"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors3",
			Valid:   []string{"LAUNCHDARKLY_TOKEN"},
			Invalid: []string{"LAUNCHDARKLY_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL:           "https://app.launchdarkly.com/api/v2/caller-identity",
		Headers:       map[string]string{"Authorization": "{key}"},
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
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
