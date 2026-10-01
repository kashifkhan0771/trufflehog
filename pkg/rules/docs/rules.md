# How the rules package works

A detector normally is a Go package: a struct, a regex, a `FromData` method, a
verification function. A rule is the same detector written as data — a value
with fields — and one runtime runs all of them.

Two packages:

| Package | What is in it |
| --- | --- |
| `pkg/rules` | The runtime. What a rule is, what makes one valid, and the code that runs it. |
| `pkg/rules/builtin` | The rules that ship. One file per provider, plus the list and the swap-in code. |

Files in `pkg/rules`:

| File | Job |
| --- | --- |
| `rule.go` | What a rule is, and `Validate`. |
| `scanner.go` | Turning a rule into a detector, and running it over a chunk. |
| `verifier.go` | The ways a credential can be checked with the provider. |
| `template.go` | Filling `{name}` into URLs, headers and bodies. |

## Life of a scan

1. The engine reads a chunk of data — 10KB, plus a 3KB peek at what
   follows, so a credential sitting across a chunk boundary is still whole in
   one of them.
2. It looks for every rule's keywords in that chunk. Case does not matter.
3. For each keyword it finds, it cuts a window around it and calls the rule's
   `FromData` with just that window.
4. The rule runs each pattern over the window. **Every pattern must match
   something.** The first one that finds nothing ends the call and the chunk
   reports nothing.
5. If a chunk holds two keys and two IDs, there is no way to know which goes
   with which, so every combination becomes a candidate.
6. Each candidate is verified, if verification is on.
7. Each candidate becomes one result.

Step 4 is why pattern order matters for speed. Matching stops at the first
empty pattern, so put the picky pattern first and the vague one last. It never
changes the answer — all patterns are required either way — but most chunks
that get this far hold no credential, so rejecting them fast is the normal
case, not the rare one.

## The Rule fields

```go
var Bugherd = rules.Rule{
    Type:        detector_typepb.DetectorType_Bugherd,
    Keywords:    []string{"bugherd"},
    Description: "Bugherd is a visual feedback and bug tracking tool ...",
    Patterns: []rules.Pattern{
        {Name: "key", Regex: `\b([0-9a-z]{22})\b`, Prefix: []string{"bugherd"}},
    },
    Test: rules.Test{ /* ... */ },
    Verify: rules.HTTP{
        URL:           "https://www.bugherd.com/api_v2/projects.json",
        BasicUser:     "{key}",
        BasicPass:     "x",
        ValidStatus:   rules.StatusCodes{200},
        InvalidStatus: rules.StatusCodes{401},
    },
}
```

### Type and Version

`Type` is the detector type from the protobuf enum. `Version` is for a provider
with two live implementations at once — GoDaddy has version 1 (the test
environment) and version 2 (production). Leave `Version` at zero when there is
only one.

Together they are the identity the engine uses. Two rules may not share both.

### Keywords

The engine will not even open a chunk for this rule unless one of these words
is in it. Matched without case.

Keep them at least 2 characters — `Validate` refuses shorter. A one-character
keyword matches nearly every chunk, and then the pre-filter stops doing its
job and the rule runs against the whole scan.

### Description

Shown to the user with the finding. Required.

### Patterns

A list of named regexes. The name is how you refer to the captured value
everywhere else: `{key}`, `{id}`.

```go
type Pattern struct {
    Name       string
    Regex      string
    Prefix     []string
    Group      *int
    MinEntropy float64
}
```

**Regex** is source text, not a compiled expression. `New` compiles it. A regex
that does not compile is a `Validate` error, and `New` panics on an invalid
rule, so it still cannot reach a scan.

**Prefix** requires one of these words to sit shortly before the value — within
about 40 characters, whatever `detectors.PrefixRegex` allows. Use it when the
regex alone would match ordinary text: `[0-9a-z]{22}` matches a hash, a
filename, half a base64 line. With a prefix it only matches when the provider's
name is next to it.

Leave `Prefix` empty for a token that identifies itself, like Stripe's
`rk_live_...` or SendGrid's `SG.`.

Two rules about `Prefix`:

- Every word in it must also be in `Keywords`. If it is not, the chunk never
  reaches the pattern, so the prefix asks for something that cannot happen.
  `Validate` catches this.
- The regex must have a capture group. The prefix becomes part of the
  expression, so without a group the captured "secret" would start at the
  keyword and include everything between. `Validate` catches this too.

**Group** picks which parenthesised group holds the secret. Leave it nil: the
default is group 1 when the regex defines one, group 0 (the whole match)
otherwise. That covers both normal ways of writing a detector regex.

**MinEntropy** throws away a captured value whose Shannon entropy is below the
number. Real keys are random and score high; `aaaaaaaaaaaa` and prose score
low. Zero, the default, means no check. It sits on the pattern, not the rule,
because the halves of one credential are not equally random — an access key ID
is not as random as its secret.

### SecretID and FullSecretID

Templates, like `"{key}"` and `"{key}{id}"`. They become the result's `Raw` and
`RawV2`.

**Treat these as a stored contract, not a formatting choice.** Both are hashed
into the identifier a finding is recorded under. Changing either one for an
existing detector does not just change this scan — every finding already stored
under the old value becomes unreachable.

So a rule replacing a hand-written detector must reproduce that detector's
`Raw` and `RawV2` exactly, including leaving `FullSecretID` empty when the
original leaves `RawV2` empty, whatever you think of the original choice.

For a genuinely new rule it is a real decision:

- **Set `FullSecretID`** (say `"{key}{id}"`) to report every combination
  separately. Use when each combination is its own credential.
- **Leave it empty** to collapse every combination sharing a `SecretID` into
  one finding. Use when the other patterns are supporting halves, and a loose
  pattern would otherwise pair one real key with every lookalike nearby and
  report the same exposed key ten times.

A single-pattern rule can leave `SecretID` empty — there is only one thing it
could mean, and `New` fills it in.

### DistinctCaptures

Drops any candidate where two patterns captured the same string.

Set it when two halves are found by the same regex, or by two regexes loose
enough to match each other's values. Amplitude's key and secret are both
`[0-9a-f]{32}`, so without this one string in the file would pair with itself
and be reported as a whole credential.

Leave it off otherwise — a provider can legitimately issue an ID and key that
happen to be identical, and this would throw that away.

### ExtraData

Extra fields on every result, verified or not. For things that are true of the
provider, like a rotation guide URL. For things only true once the credential
is confirmed live, use `HTTP.ValidExtraData` instead.

### MaxChunkSpan

How much data the engine hands the rule around the keyword, in bytes, each
side.

Leave it zero. Every rule gets a span already, matching what a hand-written
detector gets without doing anything special:

| Rule shape | Span | Same as |
| --- | --- | --- |
| One pattern | 512B | the engine's own default around a keyword match |
| Two or more patterns | 1024B | `detectors.DefaultMultiPartCredentialProvider` |
| `MaxChunkSpan` set | that number | a detector asking the engine for something else |

Two or more patterns get the wider span because an ID declared near the top of
a config file and its key declared near the bottom are still one credential,
and a window sized for a single token would see only one of them.

Set `MaxChunkSpan` when replacing a detector that asked the engine for
something other than these two defaults — Dropbox's hand-written detector
widens its own forward window to 4096 bytes for a long token, for example, so
its rule sets `MaxChunkSpan: 4096` to match. Read the detector being
replaced: a custom span is a sign it needed one, not a default to leave
unquestioned.

### Disabled

Takes the provider out of the scan completely. Read that literally: `Replace`
removes the detector from the list instead of falling back to the hand-written
one, so **nothing** looks for that provider. It is for taking a provider out of
service, not for choosing between two implementations.

A disabled rule is still validated and still needs its test data, so turning it
back on cannot surprise anyone.

### Endpoint

For a provider with more than one address a credential might verify against:
a cloud default, an address discovered in the scanned data, or one a user
configures by hand. Leave it zero for a provider with one fixed URL — most
rules do. It is the rule equivalent of a detector embedding
`detectors.EndpointSetter`.

```go
Endpoint: rules.EndpointConfig{
    Pattern: &rules.Pattern{
        Regex: `(https?://[^\s/]*\.hashicorp\.cloud(?::\d+)?)(?:/[^\s]*)?`,
    },
    Cloud: "",
},
```

**Pattern** finds a candidate endpoint in the scanned data, the same way any
other pattern finds a value, except it is never required: a chunk with no
match still reports a candidate if the cloud address or a configured one
covers it. Its `Name` is ignored — a found endpoint is always captured under
the reserved name `endpoint`, which no other pattern may use.

**Cloud** is the provider's own hosted address. Leave it empty for a
provider with no cloud offering of its own, the way HashiCorp Vault has
none — that is not an omission, some providers are genuinely self-hosted
only.

Once `Endpoint` is set, `HTTP.URL` stops being a full address and becomes a
path joined onto whichever endpoint is being tried for this candidate —
`url.JoinPath(endpoint, URL)`, the same thing a hand-written detector that
supports several addresses does by hand:

```go
Verify: rules.HTTP{
    URL:           "/v1/auth/token/lookup-self",
    Headers:       map[string]string{"X-Vault-Token": "{key}"},
    ValidStatus:   rules.StatusCodes{200},
    InvalidStatus: rules.StatusCodes{401, 403},
},
```

This is deliberately not the `{endpoint}` placeholder used everywhere else:
an endpoint chooses where the request goes, rather than filling a value into
an address the rule author already fixed, and routing it through the normal
placeholder rules would mean checking it against the wrong thing — those
rules refuse a value in the host specifically so scanned data cannot redirect
a request, which is the opposite of what an endpoint is for here.

One candidate is reported once per address `Endpoints()` returns — a cloud
address, every configured one, and (unless told otherwise) every found one —
with `endpoint` added to its captures, so `SecretID` and `FullSecretID` can
refer to it like any other pattern. **If none of those produced anything,
the candidate is dropped rather than reported unverified.** That mirrors the
hand-written detectors this replaces: a token with no address anywhere near
it, and no cloud or configured fallback, has nowhere to send a request, so
nothing is reported for it at all.

`New` turns `UseCloudEndpoint` and `UseFoundEndpoints` on by default for any
rule with `Endpoint` set. This matters because of when it happens:
`defaults.DefaultDetectors()` already does this for every hand-written
detector it builds, but `Replace` runs *after* that, building a fresh
detector rather than reusing the one being swapped out. Without `New` doing
it again, swapping in a rule would silently stop verifying against the
provider's cloud address and against addresses found in scanned data, even
though nothing asked for that — so it is not optional. A caller can still
turn either off, or add a configured endpoint, through the usual
`detectors.EndpointCustomizer` methods (the `-verifiers` CLI flag does this).

A rule with `Endpoint` set still adds a test example for `endpoint` next to
its other pattern examples — see "Testing" below for why.

### Test

The examples the rule's tests run from. See "Testing" below.

### Verify

How to check the credential with the provider. One of three.

## The three verifiers

Verification answers one of three things, not two:

| Outcome | Meaning | Reported as |
| --- | --- | --- |
| `Valid` | The provider says the credential works. | verified |
| `Invalid` | The provider rejected it. A real answer. | unverified, no error |
| `Unknown` | No answer — timeout, transport error, a status nobody planned for. | unverified, with the error attached |

Three instead of a bool because "the provider said no" and "we never got an
answer" lead to different decisions. Collapsing them either hides live
credentials behind a network blip or floods a scan with findings that were
actually disproven.

### None

No verification. Every result is unverified, nothing is contacted.

### Func

A Go function. For providers whose verification needs request signing, a
database connection, or anything a declarative rule cannot say. It is the
escape hatch that stops the rule format growing a new field every time one
provider is unusual.

### HTTP

One request, and the response decides.

```go
Verify: rules.HTTP{
    Method:            "GET",              // defaults to GET
    URL:               "https://api.example.com/v1/me",
    Headers:           map[string]string{"Authorization": "Bearer {key}"},
    Query:             map[string]string{"domain": "example.com"},
    BasicUser:         "{key}",
    BasicPass:         "x",
    Body:              map[string]string{"token": "{key}"},
    ValidStatus:       rules.StatusCodes{200, 403},
    InvalidStatus:     rules.StatusCodes{401},
    ValidBodyContains: "account",
    ValidExtraData:    map[string]string{"rotation_guide": "https://..."},
    Extract:           map[string]rules.Extract{"scopes": {JSONField: "scopes", Join: ","}},
    MaxBody:           4096,
}
```

**ValidStatus and InvalidStatus** must not overlap, and a status in neither is
`Unknown`. Both are listed on purpose instead of treating "not 2xx" as failure,
because which code means what is up to the provider. A 403 can mean the key is
real but lacks a scope for that endpoint — proof it is live. At another
provider the same code means dead. Making the rule name the codes it
understands stops it claiming an outcome for a response nobody thought about.

**Body** is a map, sent as JSON. It is a map rather than a string of JSON so
`encoding/json` does the quoting — a captured value holding a quote or a
backslash would otherwise break the body it was pasted into. `Content-Type` is
set to `application/json` unless you set it yourself.

**ValidBodyContains** further narrows a valid status: the body must contain
this substring or the outcome becomes `Invalid`. Some APIs answer 200 for
requests that failed for reasons other than the credential.

**ValidExtraData** is merged into the result only when the outcome is `Valid`.

**Extract** pulls a top-level JSON field out of the response into `ExtraData`,
so a finding can carry the scopes a token grants. An array is joined into one
string with `Join`, comma by default. Only runs on `Valid`.

A body that is not JSON, or is missing the field, is not an error. The
credential was already confirmed by its status; failing the whole verification
because a provider renamed a field would turn a true finding into a missed one.

**MaxBody** caps the read, 4 KiB by default. The body is only read at all when
`ValidBodyContains` or `Extract` is set, so most rules never pay for it.

## The {name} template

`{key}` in a URL, header, query value, body field, `BasicUser`, `BasicPass`,
`SecretID` or `FullSecretID` is replaced by what the pattern named `key`
captured.

A name is letters, digits and underscores. Anything else between braces is left
alone as ordinary text — that is what lets a body hold a GraphQL query like
`{ sshList {id, name}}` without the runtime mistaking it for a placeholder.

The one case it cannot tell apart is text that wants a literal `{key}` while
the rule also has a pattern called `key`. Rare enough to live with.

This is not `text/template` on purpose. A rule has nothing to branch on or loop
over, so the extra machinery would add a function map to audit and missing-key
behaviour to get wrong, and buy nothing.

### Why the template is careful

Every value substituted came out of scanned data. A repository can hold a
"credential" crafted to contain newlines, ampersands or slashes. So each place
a value can land is checked for that place:

| Where | What happens |
| --- | --- |
| URL scheme | Must be http or https. |
| URL host | `url.Parse` refuses a brace in a host, so a value cannot go there at all. |
| URL query | A placeholder in the URL string is refused — use `Query`, which escapes through `url.Values`. |
| URL path | Escaped as one path segment, so a value cannot add `/`, `?` or `#`. |
| Header | A value with CR or LF is refused, since it would end the header and let the rest be read as more headers. |
| Basic auth | Base64-encoded by `SetBasicAuth`, so nothing to escape. |
| Body | Values are filled in first, then `json.Marshal` escapes them. |

## Validate

`New` calls `Validate` and panics if it fails. That sounds harsh, but a rule is
a package-level value built at startup, so an invalid one is a mistake in the
source, not something that can happen mid-scan. Failing immediately beats
scanning with a detector that quietly does the wrong thing.

`Validate` reports **everything** wrong at once, joined into one error, so you
fix a new rule in one pass instead of one problem at a time.

What it checks:

- at least one keyword, and none shorter than 2 characters
- at least one pattern
- no pattern with an empty name or empty regex
- every regex compiles
- no duplicate pattern names — names address captures, so a duplicate means one
  value silently overwrote another
- every `Prefix` word is also a keyword
- every pattern with a `Prefix` has a capture group
- a multi-pattern rule names a `SecretID`
- `DistinctCaptures` is only set on a rule with two or more patterns
- `MaxChunkSpan` is not negative
- a description exists
- a verifier exists — use `None{}` for detection-only
- test examples and `NotExamples` name patterns that exist, and `NotExamples`
  lists are not empty
- every `{name}` in `SecretID`, `FullSecretID`, the URL, headers, query, body
  fields and basic auth names a pattern that exists
- the URL builds, and its scheme is http or https
- no status code is in both `ValidStatus` and `InvalidStatus`

What it does not check: whether an example actually matches its own pattern.
That would mean running the pattern against generated text — a detection
test, not a structural check of the rule — so it is `TestDetection`'s job,
not `Validate`'s. A fixed-length example written one character short, the
commonest mistake in a new rule, shows up there instead: as a test that
quietly finds nothing.

## Testing

Test data lives on the rule; the tests are generic and live in
`pkg/rules/builtin/test/`. Adding a rule adds no test code.

```go
Test: rules.Test{
    Detection: rules.DetectionTest{
        Examples:    map[string]string{"key": "47p9pb0tdbm50fqo1xo5cv"},
        NotExamples: map[string][]string{"key": {"0xzmas6en5mtmo3oqsg5l"}},
    },
    Integration: rules.IntegrationTest{
        Group:   "detectors2",
        Valid:   []string{"BUGHERD"},
        Invalid: []string{"BUGHERD_INACTIVE"},
    },
},
```

`Examples` is one value per pattern, and together they must form one whole
credential — that is why it is a single value each, not a list.

`NotExamples` is a list per pattern, because a pattern usually has more than
one boundary to guard. Each one is swapped into the otherwise-valid examples on
its own, and the rule must then find nothing.

A rule with `Endpoint.Pattern` set adds an `"endpoint"` entry to `Examples`
too, even though it is not one of `Patterns`. A rule that must find an
endpoint to report anything would otherwise never be exercised by the
detection tests, which build their sample text only from `Examples`. Give it
a plausible fake address, such as `"https://my-vault-cluster.z1.hashicorp.cloud:8200"`.
If more than one rule in the package has an endpoint pattern matching the
same shape of address, give them the *same* fake address — the detection
test that pastes every rule's examples into one document would otherwise
find each rule's endpoint pattern matching the other rule's address too, and
report a candidate your own rule's `Examples` cannot account for.

The tests in `pkg/rules/builtin/test/`:

| Test | What it proves |
| --- | --- |
| `TestDetection` | The rule finds its own credential in three shapes of text — bare, in a config file, in a log — and reports it under the right identity. |
| `TestDetectionWithEveryOtherCredential` | With all 15 credentials in one document, each rule still finds its own and nothing belonging to another rule. A rule alone can never fail this; it is the only test that catches a pattern loose enough to match another provider's key. |
| `TestRefusals` | Each half removed in turn, one value in both slots for a `DistinctCaptures` rule, and every `NotExamples` value — all must find nothing. |
| `TestShapesHoldNoCredential` | The shared text itself is clean, so findings above mean something. |
| `TestFindingIdentities` | What each rule reports findings under, against a checked-in golden file. |
| `TestEveryRuleIsTested` | Every pattern has an example, so no rule slips in untested. |
| `TestIntegrationVerification` | Behind `-tags detectors`. Asks the real provider about a real credential and a revoked one. |
| `TestAllValidate` | Every rule in `All` passes `Validate`. |
| `TestReplacePreservesOptionalInterfaces` | A rule never narrows the window or loses an interface the detector it replaces had. |

`TestFindingIdentities` exists because the other tests cannot catch a changed
`SecretID`. They work out what to expect from the rule's own templates, so
editing a template moves the expectation with it and the test still passes. The
golden file sits where the rule cannot reach it. Regenerate with:

```
go test ./pkg/rules/builtin/test -run TestFindingIdentities -update
```

A changed line there is a change to what findings are stored under. Read it
before you accept it.

## Getting rules into a scan

```go
// swap rules in for the hand-written detectors of the same type and version
detectors = builtin.Replace(detectors, nil)

// or build only the rule-backed detectors
detectors = builtin.Detectors(nil)
```

`Replace` swaps rather than appends because the engine keys detectors on type
and version — registering both implementations would leave which one runs down
to map ordering. Order is preserved, and a detector with no matching rule is
returned untouched.

`main.go` calls `Replace`.

## What a rule cannot do yet

If the detector you are replacing has any of these, the rule cannot stand in
for it, and `TestReplacePreservesOptionalInterfaces` will say so:

- **Custom results cleaner** — its own logic for dropping duplicate results.
- **Custom false positive checker** — its own filtering beyond patterns.

Endpoint customization — user-configured or discovered endpoints, for
self-hosted providers — a rule can express. See "Endpoint" below.

Also capped: one chunk produces at most 100 candidates. Two loose patterns with
fifty matches each would otherwise be 2,500 candidates and 2,500 verification
requests, and one unusual file would turn into a flood of traffic at the
provider.
