package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Stripe live secret and restricted keys. Test keys ("sk_test") are
// deliberately not matched. A 403 indicates a restricted key without access to
// the charges endpoint, which still confirms the key is live.
var Stripe = rules.Rule{
	Type:     detector_typepb.DetectorType_Stripe,
	Keywords: []string{"k_live"},
	Description: "Stripe is a payment processing platform. Stripe API keys can be used to interact with " +
		"Stripe's services for processing payments, managing subscriptions, and more.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `[rs]k_live_[a-zA-Z0-9]{20,247}`},
	},
	ExtraData: map[string]string{"rotation_guide": "https://howtorotate.com/docs/tutorials/stripe/"},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "rk_live_D53X83RZJzzzzgEOzdmenCkhvMdgaK"},
			NotExamples: map[string][]string{"key": {"rk_live_jIg8xNbe3nNyjOq9wMx"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors2",
			Valid:   []string{"STRIPE_SECRET"},
			Invalid: []string{"STRIPE_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL: "https://api.stripe.com/v1/charges",
		Headers: map[string]string{
			"Authorization": "Bearer {key}",
			"Content-Type":  "application/json",
		},
		ValidStatus:   rules.StatusCodes{200, 403},
		InvalidStatus: rules.StatusCodes{401},
	},
}
