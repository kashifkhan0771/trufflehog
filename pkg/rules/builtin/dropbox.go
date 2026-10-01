package builtin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// Dropbox access tokens.
//
// Verification cannot be described as a plain request and response, so it uses
// a function. Dropbox answers 401 both for a token that is dead and for a token
// that is alive but lacks the scope for this endpoint, and only the body says
// which. A live-but-unscoped token is still an exposed credential, so the body
// has to be read before the 401 can be called a rejection.
var Dropbox = rules.Rule{
	Type:     detector_typepb.DetectorType_Dropbox,
	Keywords: []string{"dropbox", "sl."},
	Description: "Dropbox is a file hosting service that offers cloud storage, file synchronization, " +
		"personal cloud, and client software. Dropbox API keys can be used to access and manage files and " +
		"folders in a Dropbox account.",
	Patterns: []rules.Pattern{
		{Name: "token", Regex: `\b(sl\.(u\.)?[A-Za-z0-9\-\_]{130,})\b`, Prefix: []string{"dropbox"}},
	},
	// The token has no upper length bound and a short-lived scoped token
	// (sl.u.…) can run to ~1.5KB, which is why the hand-written detector
	// widens its own window from the engine's default via MaxSecretSize(4096)
	// - asymmetrically, forward only. This runtime's span is symmetric, so
	// matching that number here reaches exactly as far forward and further
	// back than the original did, never less either way.
	MaxChunkSpan: 4096,
	Test: rules.Test{
		Detection: rules.DetectionTest{
			Examples:    map[string]string{"token": "sl.Dm7ena8D5VfLDpgyyjVw5HanSBeVRsfAGeAbP0VxNjAe_9i0mYtluYI0KN1gNT11cUzYZAa3u2olZU6uqbgsYlVvsSKuvinX-zMqf9OgXluCZz8xBfZuXTptFyfePpX6N1NF2XV"},
			NotExamples: map[string][]string{"token": {"sl.54wca-7E56w8ZniqT3Ul4ffqkOkgWrdioyq-KvCiSGuPJ6sG9AHEOVezxZuJPWvHogU5nGYVHWVsUQk4DwgLGNOaeCtL31Ugq-DfcgaTMnTC0MrAU8urbFt5misIZHbhS"}},
		},
		Integration: rules.IntegrationTest{
			Group:   "detectors2",
			Valid:   []string{"DROPBOX"},
			Invalid: []string{"DROPBOX_INACTIVE"},
		},
	},
	Verify: rules.Func(verifyDropbox),
}

// verifyDropbox asks Dropbox to describe the account a token belongs to.
func verifyDropbox(ctx context.Context, captures rules.Captures, client *http.Client) (rules.Outcome, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.dropboxapi.com/2/users/get_current_account", nil)
	if err != nil {
		return rules.Unknown, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+captures["token"])

	res, err := client.Do(req)
	if err != nil {
		return rules.Unknown, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode == http.StatusOK {
		return rules.Valid, nil, nil
	}
	// Any other status is not something this rule claims to understand.
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusBadRequest {
		return rules.Unknown, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}

	// Read enough of the body to tell a dead token from a live one that was
	// turned away for lacking a scope.
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<10))
	if err != nil {
		return rules.Unknown, nil, err
	}
	text := string(body)
	switch {
	case strings.Contains(text, "missing_scope"),
		strings.Contains(text, "does not have the required scope"):
		return rules.Valid, nil, nil
	case strings.Contains(text, "invalid_access_token"),
		strings.Contains(text, "expired_access_token"):
		return rules.Invalid, nil, nil
	default:
		return rules.Unknown, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}
