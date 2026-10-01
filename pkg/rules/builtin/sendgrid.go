package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
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
		{Name: "key", Regex: `\bSG\.[\w\-]{20,24}\.[\w\-]{39,50}\b`},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "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"},
			NotExamples: map[string][]string{"key": {"SG.ORS-6ilI8ihN5KXSc7Tvo-.hBKqFYY-kv5ZJr3J1TWDtkwtDDb_xHKas1VOqg"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors5",
			Valid:   []string{"SENDGRID"},
			Invalid: []string{"SENDGRID_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		URL: "https://api.sendgrid.com/v3/scopes",
		Headers: map[string]string{
			"Authorization": "Bearer {key}",
			"Content-Type":  "application/json",
		},
		ValidStatus:    rules.StatusCodes{200, 403},
		InvalidStatus:  rules.StatusCodes{401},
		ValidExtraData: map[string]string{"rotation_guide": "https://howtorotate.com/docs/tutorials/sendgrid/"},
		Extract:        map[string]rules.Extract{"scopes": {JSONField: "scopes", Join: ","}},
	},
}
