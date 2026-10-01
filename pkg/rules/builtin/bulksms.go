package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// BulkSMS credentials, which are an ID and a key used together as the basic
// auth username and password.
var Bulksms = rules.Rule{
	Type:     detector_typepb.DetectorType_Bulksms,
	Keywords: []string{"bulksms"},
	Description: "BulkSMS is a service used for sending SMS messages in bulk. BulkSMS credentials can be " +
		"used to access and send messages through the BulkSMS API.",
	Patterns: []rules.Pattern{
		{Name: "id", Regex: `\b([A-F0-9-]{37})\b`, Prefix: []string{"bulksms"}},
		{Name: "key", Regex: `\b([a-zA-Z0-9!@#$%^&*()]{29})\b`, Prefix: []string{"bulksms"}},
	},
	SecretID:     "{key}",
	FullSecretID: "{key}{id}",
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples: map[string]string{"id": "8B36548FDAC2C57D06537CB90580459A716B6", "key": "6Uk$zYuF0ie9(*Pu2njHkAm1@5wDr"},
			NotExamples: map[string][]string{
				"id":  {"B8CB20C4524B2423ACA1D986279E9FA3E144"},
				"key": {"16E&pLLJIVGHz4FxFEtKyPiYGF#^"},
			},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors3",
			Valid:   []string{"BULKSMS", "BULKSMS_TOKEN"},
			Invalid: []string{"BULKSMS_INACTIVE", "BULKSMS_TOKEN"},
		},
	},
	Verify: rules.HTTP{
		URL:           "https://api.bulksms.com/v1/messages",
		BasicUser:     "{id}",
		BasicPass:     "{key}",
		ValidStatus:   rules.StatusCodes{200},
		InvalidStatus: rules.StatusCodes{401},
	},
}
