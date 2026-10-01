# How to add a rule

A rule is a detector written as data. Adding one means writing one file and
adding one line to a list. No new package, no `FromData`, no test file.

Read `rules.md` first if you want to know why each field exists. This page is
the steps.

## Before you start

Most rules replace a hand-written detector. **Open that detector and read it.**
You need three things from it:

1. Its regexes and keywords.
2. What it puts in `Raw` and `RawV2`.
3. What it treats as verified - which status codes, which endpoint.

Number 2 matters most. `Raw` and `RawV2` are hashed into the identifier a
finding is stored under. If your rule reports different values, every finding
already stored for that detector becomes unreachable. Copy them exactly, even
if you would have chosen differently.

## Step 1: Write the rule file

One file per provider, named after it, in `pkg/rules/builtin/`.

Start from a generated skeleton rather than copying another rule, so you get
every field with its decision points instead of whichever ones that rule
happened to use.

If the provider already has a hand-written detector, read it in:

```
make rule-from-detector NAME=Bugherd
```

It finds the package whose `Type()` reports that detector type and fills in
what it can read: keywords, description, patterns with their prefixes, the
verification URL, headers, basic auth, the status codes, and `SecretID` /
`FullSecretID` derived from the detector's own `SecretParts` mapping. Anything
it cannot read cleanly becomes a TODO, and it prints exactly what it skipped
and why, so nothing looks filled in when it was guessed.

Across all 932 detector packages it reads keywords and descriptions from 98%,
patterns from 96%, `SecretID` from 97%, the URL from 70% and status codes from
29%. The last number is low because most detectors decide on the response body
as well as the status, and there the status alone means nothing definite.

**Check `SecretID` and `FullSecretID` against the detector by hand anyway.**
They are hashed into the identifier findings are stored under.

For a provider with no detector yet:

```
make rule NAME=Beehiiv
```

Either way the file does not compile until the TODOs are filled in, which is
the point — a half-finished rule should not build.

Filled in, it looks like this:

```go
// pkg/rules/builtin/bugherd.go
package builtin

import (
    "github.com/trufflesecurity/trufflehog/v3/pkg/rules"
    "github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// Bugherd API keys. The key is sent as the basic auth username with a
// throwaway password, which is how the provider expects a key-only credential.
var Bugherd = rules.Rule{
    Type:     detector_typepb.DetectorType_Bugherd,
    Keywords: []string{"bugherd"},
    Description: "Bugherd is a visual feedback and bug tracking tool for " +
        "websites. Bugherd API keys can be used to access and manage projects.",
    Patterns: []rules.Pattern{
        {Name: "key", Regex: `\b([0-9a-z]{22})\b`, Prefix: []string{"bugherd"}},
    },
    Test: rules.Test{
        Detection: rules.DetectionTest{
            Examples:    map[string]string{"key": "47p9pb0tdbm50fqo1xo5cv"},
            NotExamples: map[string][]string{
                "key": {"0xzmas6en5mtmo3oqsg5l", "o50djzdnbj0ddlz2uhfkvml"},
            },
        },
        Integration: rules.IntegrationTest{
            Group:   "detectors2",
            Valid:   []string{"BUGHERD"},
            Invalid: []string{"BUGHERD_INACTIVE"},
        },
    },
    Verify: rules.HTTP{
        URL:           "https://www.bugherd.com/api_v2/projects.json",
        BasicUser:     "{key}",
        BasicPass:     "x",
        ValidStatus:   rules.StatusCodes{200},
        InvalidStatus: rules.StatusCodes{401},
    },
}
```

That is a whole detector.

### Filling in the patterns

Name each pattern after what it is: `key`, `secret`, `id`, `username`. The name
is how you refer to the value later — `{key}` in the header, `{key}{id}` in
`FullSecretID`.

Write the regex as plain text, no `regexp.MustCompile`. The runtime compiles it.

Add `Prefix` when the regex alone would match ordinary text. `[0-9a-z]{22}`
matches a hash or a filename just as happily as a key, so it needs the word
`bugherd` nearby to mean anything. Two rules:

- Every `Prefix` word must also be in `Keywords`.
- The regex needs a capture group, `( )`. Without one the captured value would
  include the keyword.

Skip `Prefix` for a token that names itself — `SG.`, `rk_live_`, `endr+`.

Put the pickiest pattern first. Matching stops at the first pattern that finds
nothing, so that is the cheapest way to reject a chunk.

### Filling in the identity

One pattern: leave `SecretID` empty, the runtime fills it in.

Two or more: say what identifies the credential.

```go
SecretID:     "{key}",
FullSecretID: "{key}{id}",
```

Copy these from the detector you are replacing. `Raw` becomes `SecretID`,
`RawV2` becomes `FullSecretID`. If the old detector left `RawV2` empty, leave
`FullSecretID` empty.

If two patterns can match each other's values — same regex, or two loose
ones — add `DistinctCaptures: true`, or one string in the file will pair with
itself and be reported as a whole credential.

### Filling in the verifier

Most providers: one HTTP request.

```go
Verify: rules.HTTP{
    URL:           "https://api.example.com/v1/me",
    Headers:       map[string]string{"Authorization": "Bearer {key}"},
    ValidStatus:   rules.StatusCodes{200},
    InvalidStatus: rules.StatusCodes{401},
},
```

List the codes you actually understand. Do not add a code because it looks like
success — a status in neither list becomes `Unknown`, which is the honest
answer for a response nobody planned for. A 403 is worth thinking about: at
some providers it means the key is live but lacks a scope, which is proof it
works.

No verification endpoint? Use `rules.None{}`. Verification that needs signing
or a database connection? Use `rules.Func`.

### Self-hosted providers, or more than one address

If the hand-written detector embeds `detectors.EndpointSetter`, set
`Rule.Endpoint` instead of a fixed `URL`. See "Endpoint" in `rules.md` for the
full shape; in outline:

```go
Endpoint: rules.EndpointConfig{
    Pattern: &rules.Pattern{Regex: `...address found in scanned data...`},
    Cloud:   "https://api.example.com", // or "" if there is no cloud offering
},
Verify: rules.HTTP{
    URL: "/v1/me", // a path now, joined onto whichever endpoint is tried
    ...
},
```

Copy the detector's own found-endpoint regex and its `CloudEndpoint()` value.
Add an `"endpoint"` entry to `Test.Detection.Examples` so the detection tests
have something to find — a rule that needs an endpoint to report anything
finds nothing in sample text built only from its other patterns.

## Step 2: Add test data

Two fields, both on the rule. No test file.

```go
Examples:    map[string]string{"key": "47p9pb0tdbm50fqo1xo5cv"},
NotExamples: map[string][]string{"key": {"0xzmas6en5mtmo3oqsg5l"}},
```

**Examples** — one fake value per pattern. Together they must be a complete,
valid-looking credential, because the tests build text from them and expect the
rule to find exactly them.

**NotExamples** — values the pattern must refuse.

Write each one character off the boundary. For `{22}`, write a 21-character
value and a 23-character one. A value that is far outside the pattern still
passes after someone loosens the regex by mistake, which is the exact bug these
exist to catch.

Keep the values obviously fake. They are compiled into the binary.

## Step 3: Add the integration test data

This is the live test, behind a build tag. It reads real credentials from the
project's secret manager. Only field names go in the rule, never values.

```go
Integration: rules.IntegrationTest{
    Group:   "detectors2",
    Valid:   []string{"BUGHERD"},
    Invalid: []string{"BUGHERD_INACTIVE"},
},
```

Take the group and field names from the hand-written detector's integration
test — they are already there. Some providers hold the whole credential in one
field, some split it over two, which is why these are lists.

Leave `Integration` out entirely if there is no live test.

## Step 4: Add it to the list

In `pkg/rules/builtin/builtin.go`:

```go
var All = []rules.Rule{
    AbuseIPDB,
    AmplitudeApiKey,
    Bugherd,        // <- yours
    ...
}
```

A rule missing from here is registered nowhere. The list is written by hand so
one place shows every rule that ships.

## Step 5: Run the tests

```
go test ./pkg/rules/...
```

That runs everything except the live test. What can go wrong:

**`Validate` failed.** It reports every problem at once, so read the whole
error. These are structural mistakes in the rule itself — an empty regex, a
`Prefix` word missing from `Keywords`, a template referencing a pattern that
does not exist.

**`TestDetection` failed.** The rule did not find its credential in one of the
three shapes of text, or found something extra. The commonest cause is an
example that does not match its own regex — usually one character short.

**`TestDetectionWithEveryOtherCredential` failed.** Your pattern matched
another provider's key. Almost always a missing `Prefix`.

**`TestRefusals` failed.** A `NotExample` was matched, or a rule with two
patterns still reported something with one half removed.

**`TestFindingIdentities` failed.** Expected for a new rule — the golden file
does not know about it yet. See the next step.

## Step 6: Update the golden file

```
go test ./pkg/rules/builtin/test -run TestFindingIdentities -update
```

This writes `pkg/rules/builtin/test/testdata/findings.txt`, which records
what every rule reports findings under.

**Read the diff before committing it.** A new line for your rule is expected. A
changed line for a rule you did not touch means you changed what findings are
stored under, and that strands everything already stored.

## Step 7: Run the live test

Needs the build tag and access to the project's secret manager.

```
go test -tags detectors ./pkg/rules/builtin/test -run TestIntegrationVerification
```

It checks both halves: a working credential must come back verified, and a
revoked one must come back definitively rejected rather than merely
unconfirmed.

The revoked half is the one worth having. A verifier pointed at the wrong URL
still reports a live credential as live. Only the revoked credential shows
whether the rule is really asking the provider anything.

## Step 8: Leave the old detector alone

If the rule replaces a hand-written detector, that detector's package stays
where it is — `Replace` swaps it out at startup, and the old code is still
there to compare against. Do not delete it in the same change.

## A multi-pattern example

One credential made of two halves, found separately:

```go
var Aylien = rules.Rule{
    Type:     detector_typepb.DetectorType_Aylien,
    Keywords: []string{"aylien"},
    Description: "Aylien is a text analysis platform ...",
    Patterns: []rules.Pattern{
        {Name: "key", Regex: `\b([a-z0-9]{32})\b`, Prefix: []string{"aylien"}},
        {Name: "id", Regex: `\b([a-z0-9]{8})\b`, Prefix: []string{"aylien"}},
    },
    SecretID:     "{key}",
    FullSecretID: "{key}{id}",
    Test: rules.Test{
        Detection: rules.DetectionTest{
            Examples: map[string]string{
                "key": "6846p7q9m2i0hz2uep1enthjxjqi3ogz",
                "id":  "rclri1qz",
            },
            NotExamples: map[string][]string{
                "key": {"5kok16zv0mwufxbv932byv7s6ehogfq"},  // 31 characters
                "id":  {"j865ufr"},                          // 7 characters
            },
        },
        Integration: rules.IntegrationTest{
            Group:   "detectors1",
            Valid:   []string{"AYLIEN", "AYLIEN_ID"},
            Invalid: []string{"AYLIEN_INACTIVE", "AYLIEN_ID"},
        },
    },
    Verify: rules.HTTP{
        URL: "https://api.aylien.com/news/stories",
        Headers: map[string]string{
            "X-AYLIEN-NewsAPI-Application-ID":  "{id}",
            "X-AYLIEN-NewsAPI-Application-Key": "{key}",
        },
        ValidStatus:   rules.StatusCodes{200},
        InvalidStatus: rules.StatusCodes{401},
    },
}
```

Differences from the single-pattern case:

- Both patterns are required. One half alone reports nothing.
- `SecretID` must be named — the runtime cannot guess which capture is the
  secret.
- The rule automatically gets a 1024-byte window instead of 512, matching
  `detectors.DefaultMultiPartCredentialProvider`, because the two halves can
  sit further apart than a single token. You do not set anything for that —
  unless the detector you are replacing asked the engine for something wider
  still, in which case set `MaxChunkSpan` to match it. See
  "MaxChunkSpan" in `rules.md`.

## Turning a rule off

```go
Disabled: true,
```

This removes the provider from the scan entirely — the hand-written detector
goes with it, so nothing looks for that provider at all. It is not a way to
fall back to the old implementation.

A disabled rule is still validated and still needs its test data, so turning it
back on later cannot surprise anyone.

## Checklist

- [ ] Read the detector you are replacing
- [ ] `Raw` → `SecretID`, `RawV2` → `FullSecretID`, copied exactly
- [ ] Every `Prefix` word is also in `Keywords`
- [ ] Every pattern with a `Prefix` has a capture group
- [ ] `NotExamples` are one character off the boundary
- [ ] If the detector embeds `EndpointSetter`, `Rule.Endpoint` is set and
      `Test.Detection.Examples` has an `"endpoint"` value
- [ ] If the detector implements `MaxSecretSizeProvider`, `StartOffsetProvider`,
      or a `MultiPartCredentialProvider` span wider than the default, set
      `MaxChunkSpan` to match
- [ ] Added to `All`
- [ ] `go test ./pkg/rules/...` passes
- [ ] Golden file updated, and the diff only shows your rule
- [ ] Live test run, both valid and revoked
