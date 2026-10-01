// This file holds the small template language a rule uses: "{name}" in a URL,
// header, body field or identity template is swapped for the value captured by
// the pattern of that name.

package rules

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// eachPlaceholder walks tmpl once and calls found for every "{name}" in it,
// handing over the text that came just before. It returns whatever text is
// left after the last one.
//
// One walker means render and placeholders agree by construction about what
// counts as a placeholder, instead of each keeping its own copy of the rule.
//
// This is deliberately not text/template. A rule has nothing to branch on or
// loop over, so the extra machinery would buy nothing while adding a function
// map to audit and missing-key behaviour to get wrong.
func eachPlaceholder(tmpl string, found func(before, name string)) (rest string) {
	// Braces already looked at and kept as plain text. Searching starts after
	// them so a brace that is not a placeholder is not examined twice.
	searchFrom := 0
	for {
		openIdx := strings.IndexByte(tmpl[searchFrom:], '{')
		if openIdx < 0 {
			return tmpl
		}
		// IndexByte searched a slice of the template, so shift both offsets
		// back to positions in the whole string.
		openIdx += searchFrom
		closeIdx := strings.IndexByte(tmpl[openIdx:], '}')
		if closeIdx < 0 {
			return tmpl
		}
		closeIdx += openIdx

		name := tmpl[openIdx+1 : closeIdx]
		if !isPlaceholderName(name) {
			// These braces wrap something that is not a pattern name, so they
			// belong to the text. That is what lets a value hold braces of its
			// own, such as the GraphQL query "{ sshList {id, name}}".
			//
			// The one thing this cannot tell apart is text that wants a
			// literal {key} while the rule also has a pattern named key. Rare
			// enough to live with; the alternative is an escape character in
			// every such value.
			searchFrom = openIdx + 1
			continue
		}
		found(tmpl[:openIdx], name)
		tmpl = tmpl[closeIdx+1:]
		searchFrom = 0
	}
}

// isPlaceholderName reports whether s looks like a pattern name: a non-empty
// run of letters, digits and underscores. Anything with a space, quote, colon
// or comma in it came from the surrounding text rather than from a rule author
// naming a capture.
func isPlaceholderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// render replaces every "{name}" in tmpl with the value captured by the pattern
// called name. A name the rule never declared renders as empty, but Validate
// rejects that at construction time, so it should not reach here.
func render(tmpl string, captures Captures) string {
	// Overwhelmingly common case: a constant with no placeholders at all.
	if !strings.ContainsRune(tmpl, '{') {
		return tmpl
	}
	var out strings.Builder
	out.Grow(len(tmpl))
	rest := eachPlaceholder(tmpl, func(before, name string) {
		out.WriteString(before)
		out.WriteString(captures[name])
	})
	out.WriteString(rest)
	return out.String()
}

// placeholders returns every name referenced by "{...}" in tmpl. Validate uses
// it to catch a rule that refers to a pattern it never declared, which would
// otherwise show up as an empty value in a request at scan time.
func placeholders(tmpl string) []string {
	var names []string
	eachPlaceholder(tmpl, func(_, name string) {
		names = append(names, name)
	})
	return names
}

// renderURL builds the URL to verify one candidate against.
//
// Everything it substitutes came out of scanned data, so a repository can hold
// a "credential" shaped to send the request somewhere else. The whole job of
// this function is to make sure a rule always talks to the provider it named:
// only HTTP and HTTPS, no value in the host or query, and path values escaped
// so they stay one segment.
func renderURL(tmpl string, captures Captures) (*url.URL, error) {
	// Look at the template first, while the "{name}" parts are still visible,
	// so we can tell which piece of the URL each value is filling. url.Parse
	// refuses a brace in the host, so a rule cannot put a value there at all.
	template, err := url.Parse(tmpl)
	if err != nil {
		return nil, err
	}
	if template.Scheme != "http" && template.Scheme != "https" {
		return nil, fmt.Errorf("verification URL scheme %q is not http(s)", template.Scheme)
	}
	if len(placeholders(template.RawQuery)) > 0 {
		return nil, errors.New("verification URL query holds a placeholder; put it in Query instead")
	}

	// So a value can only land in the path, and it is escaped as one path
	// segment before it goes in. That takes away the "/", "?" and "#" a value
	// would need to point the request somewhere the rule did not choose.
	return url.Parse(render(tmpl, escapedForPath(captures)))
}

// escapedForPath copies captures with every value escaped for use as a single
// path segment.
func escapedForPath(captures Captures) Captures {
	escaped := make(Captures, len(captures))
	for name, value := range captures {
		escaped[name] = url.PathEscape(value)
	}
	return escaped
}
