// This file holds what makes a Rule valid: Validate itself, and every check
// it runs.

package rules

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
)

// Validate reports everything wrong with a rule at once, joined into a single
// error, so a rule author sees every problem in one run instead of fixing them
// one at a time.
//
// New calls it and panics on failure. A Rule is a package-level value built at
// startup, so an invalid one is a mistake in the source rather than something
// that can happen part way through a scan, and failing immediately is better
// than scanning with a detector that quietly does the wrong thing.
func (r Rule) Validate() error {
	compiled, problems := r.compile()
	endpoint, err := r.compileEndpoint()
	if err != nil {
		problems = append(problems, fmt.Errorf("%s: %w", r.identity(), err))
	}
	return r.validate(compiled, endpoint, problems)
}

// validate holds the checks themselves, working from patterns that are already
// compiled. New compiles once and calls this, rather than calling Validate and
// compiling a second time.
func (r Rule) validate(compiled []compiledPattern, endpoint *compiledPattern, problems []error) error {
	// Every problem names the rule it belongs to. Without it, one invalid
	// rule's problems read the same as another's, and a batch of several
	// broken rules - everything Validate reports from one, errors.Join of
	// several - becomes a guessing game about which line is whose. See
	// Rule.identity.
	identity := r.identity()
	addProblem := func(format string, args ...any) {
		problems = append(problems, fmt.Errorf("%s: %s", identity, fmt.Sprintf(format, args...)))
	}

	if len(r.Keywords) == 0 {
		addProblem("no keywords")
	}
	for _, keyword := range r.Keywords {
		// Keywords feed the engine's pre-filter, which decides which chunks
		// are worth running this rule against. A single character matches
		// almost everything, so the rule would run on every chunk in the scan
		// and the pre-filter would stop doing its job.
		if len(keyword) < 2 {
			addProblem("keyword %q is shorter than 2 characters", keyword)
		}
	}

	if len(r.Patterns) == 0 {
		addProblem("no patterns")
	}
	patternNames := make(map[string]bool, len(r.Patterns)+1)
	// "endpoint" is a valid reference - in a template, or as a test example -
	// only once Rule.Endpoint says a candidate will actually carry one.
	if r.Endpoint.configured() {
		patternNames[endpointCaptureName] = true
	}
	for _, pattern := range r.Patterns {
		if pattern.Name == "" || pattern.Regex == "" {
			addProblem("pattern with empty name or regex")
			continue
		}
		// Names address captures, so a duplicate would mean one pattern's
		// value silently overwrote another's. "endpoint" is reserved for
		// Rule.Endpoint, whether or not this rule uses it, so a provider
		// cannot have a pattern that only collides once Endpoint is added.
		if pattern.Name == endpointCaptureName {
			addProblem("pattern name %q is reserved for Rule.Endpoint", endpointCaptureName)
		}
		if patternNames[pattern.Name] {
			addProblem("duplicate pattern name %q", pattern.Name)
		}
		patternNames[pattern.Name] = true

		// A prefix word the keywords do not include asks for something that
		// cannot happen: the engine only hands this rule chunks holding a
		// keyword, so a value introduced by that word alone is never seen.
		for _, prefix := range pattern.Prefix {
			if !slices.Contains(r.Keywords, prefix) {
				addProblem("pattern %q requires the prefix %q, which is not one of the rule's keywords",
					pattern.Name, prefix)
			}
		}
	}

	// A prefix becomes part of the expression, so a pattern that captures its
	// whole match would report the keyword and the characters between it and
	// the value as part of the secret. Group 0 is that whole match, and it is
	// also the default when the regex defines no group of its own.
	for _, pattern := range compiled {
		if len(pattern.Prefix) == 0 || pattern.regex == nil {
			continue
		}
		group := 1
		if pattern.Group != nil {
			group = *pattern.Group
		}
		if group == 0 || pattern.regex.NumSubexp() == 0 {
			addProblem("pattern %q has a prefix but captures its whole match, which would include the keyword",
				pattern.Name)
		}
	}

	if r.Endpoint.Pattern != nil {
		if r.Endpoint.Pattern.Name != "" {
			addProblem("Endpoint.Pattern.Name must be left empty; a found endpoint is always captured as {%s}",
				endpointCaptureName)
		}
		if r.Endpoint.Pattern.Regex == "" {
			addProblem("Endpoint.Pattern has an empty regex")
		}
		for _, prefix := range r.Endpoint.Pattern.Prefix {
			if !slices.Contains(r.Keywords, prefix) {
				addProblem("Endpoint.Pattern requires the prefix %q, which is not one of the rule's keywords", prefix)
			}
		}
		if endpoint != nil && endpoint.regex != nil && len(endpoint.Prefix) > 0 {
			group := 1
			if endpoint.Group != nil {
				group = *endpoint.Group
			}
			if group == 0 || endpoint.regex.NumSubexp() == 0 {
				addProblem("Endpoint.Pattern has a prefix but captures its whole match, which would include the keyword")
			}
		}
	}

	// SecretID cannot be guessed once there is more than one pattern, since
	// which capture identifies the credential is a decision only the rule
	// author can make. FullSecretID is deliberately not required here: leaving it
	// empty is a valid choice that collapses combinations into one finding.
	if len(r.Patterns) > 1 && r.SecretID == "" {
		addProblem("multi-pattern rule has no SecretID")
	}
	// With one pattern there is no second slot for a value to collide with,
	// so asking for distinct captures means the rule author expected
	// something this flag does not do.
	if r.DistinctCaptures && len(r.Patterns) < 2 {
		addProblem("DistinctCaptures needs at least two patterns")
	}
	if r.MaxChunkSpan < 0 {
		addProblem("MaxChunkSpan is negative")
	}
	if r.Description == "" {
		addProblem("no description")
	}
	if r.Verify == nil {
		addProblem("no verifier (use None{} for detection-only rules)")
	}

	// Test examples have to name real patterns. Whether an example is
	// actually something its own pattern captures is not checked here: that
	// runs the pattern against generated text, which is a detection test,
	// not a structural check of the rule - TestDetection already runs it,
	// and fails there if an example does not match its own pattern.
	for name := range r.Test.Detection.Examples {
		if !patternNames[name] {
			addProblem("test example names unknown pattern %q", name)
		}
	}
	for name, values := range r.Test.Detection.NotExamples {
		if !patternNames[name] {
			addProblem("test NotExamples names unknown pattern %q", name)
		}
		if len(values) == 0 {
			addProblem("test NotExamples for %q is empty", name)
		}
	}

	// Every template may only refer to patterns this rule actually declares.
	checkTemplate := func(field, tmpl string) {
		for _, name := range placeholders(tmpl) {
			if !patternNames[name] {
				addProblem("%s references unknown pattern {%s}", field, name)
			}
		}
	}
	checkTemplate("SecretID", r.SecretID)
	checkTemplate("FullSecretID", r.FullSecretID)

	if httpVerifier, ok := r.Verify.(HTTP); ok {
		checkTemplate("URL", httpVerifier.URL)
		if r.Endpoint.configured() {
			// URL is a path joined onto whichever endpoint is tried, not a
			// full address, so it is never expected to carry its own
			// scheme — check it joins cleanly instead of parsing as one.
			if _, err := url.JoinPath("https://example.com", httpVerifier.URL); err != nil {
				addProblem("URL: %v", err)
			}
		} else {
			// Build the URL once with no values, so a template that could
			// never produce a safe address fails here rather than mid-scan.
			if _, err := renderURL(httpVerifier.URL, nil); err != nil {
				addProblem("URL: %v", err)
			}
		}
		for name, tmpl := range httpVerifier.Body {
			checkTemplate("body field "+name, tmpl)
		}
		for name, tmpl := range httpVerifier.Headers {
			checkTemplate("header "+name, tmpl)
		}
		for name, tmpl := range httpVerifier.Query {
			checkTemplate("query "+name, tmpl)
		}
		checkTemplate("BasicUser", httpVerifier.BasicUser)
		checkTemplate("BasicPass", httpVerifier.BasicPass)

		// A code in both sets has no defined meaning, and whichever check ran
		// first would decide the outcome.
		for _, code := range httpVerifier.ValidStatus {
			if httpVerifier.InvalidStatus.contains(code) {
				addProblem("status %d is listed as both ValidStatus and InvalidStatus", code)
			}
		}
	}
	return errors.Join(problems...)
}
