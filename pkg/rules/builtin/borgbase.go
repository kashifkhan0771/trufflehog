package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Borgbase API keys, checked against a GraphQL endpoint.
//
// The endpoint answers 200 whether or not the token was accepted, so the status
// alone proves nothing: a live token is only confirmed when the response
// carries the query's own result.
var Borgbase = rules.Rule{
	Type:     detector_typepb.DetectorType_Borgbase,
	Keywords: []string{"borgbase"},
	Description: "Borgbase is a service for hosting Borg repositories. Borgbase API keys can be used to " +
		"manage and access these repositories.",
	Patterns: []rules.Pattern{
		{Name: "key", Regex: `\b([a-zA-Z0-9/_.-]{148,152})\b`, Prefix: []string{"borgbase"}},
	},
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"key": "f6xuI5aHUQPFeNBTxaQWk8J.zF.alHlsZfYcMMDktXP_tKsf-2.r.cDkdfrUnW5gcF/Ha6i.li8GjHEAD6_Wj9KfzjsQGMrb9h/ImB/LK777pzNk8cL6j.5IXAAjlsHUq-JoUD_/Ydua/5ZMs1SWOp"},
			NotExamples: map[string][]string{"key": {"QaPRYpzbLGViYXjU2JgJngKtFI3-OyV2dZAkg05rK/gqv81RKMGHZEM9YpvujA._C5Q52ryFlwRlOEVHzc0X0AWIRh_JUq.BlIFXZ53Ncqe28/ajY75FnCttn6kfaqDeMqG3omjMyXHCabM6JOF"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors2",
			Valid:   []string{"BORGBASE"},
			Invalid: []string{"BORGBASE_INACTIVE"},
		},
	},
	Verify: rules.HTTP{
		Method: "POST",
		URL:    "https://api.borgbase.com/graphql",
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer {key}",
		},
		Body:              map[string]string{"query": "{ sshList {id, name}}"},
		ValidStatus:       rules.StatusCodes{200},
		InvalidStatus:     rules.StatusCodes{401},
		ValidBodyContains: `"sshList":[]`,
	},
}
