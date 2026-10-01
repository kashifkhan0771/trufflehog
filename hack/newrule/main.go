// newrule writes the skeleton of a rule file into pkg/rules/builtin.
//
// It fills in the parts that follow from the name and leaves a TODO at every
// point that needs a decision, so a new rule starts from the full set of
// fields rather than from whichever existing rule happened to be copied.
//
// With -from, it also reads the hand-written detector of that type and fills
// in whatever it can: keywords, description, patterns, the verification
// request, the status codes, and the identity templates. Every part is read
// independently, so a detector written in a shape this does not understand
// still produces a usable file with TODOs where the reading stopped. What was
// skipped is printed afterwards.
//
// Usage:
//
//	go run ./hack/newrule Beehiiv
//	go run ./hack/newrule -from Bugherd
//	make rule NAME=Beehiiv
//	make rule-from-detector NAME=Bugherd
//
// The generated file does not compile until the TODOs are filled in. That is
// deliberate: a skeleton that builds is a skeleton that can be forgotten
// half-finished.
package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

const (
	builtinDir = "pkg/rules/builtin"
	todo       = "TODO"
)

func main() {
	from := flag.Bool("from", false, "read the hand-written detector of this type and fill in what it can")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run ./hack/newrule [-from] <RuleName>")
		fmt.Fprintln(os.Stderr, "example: go run ./hack/newrule -from Bugherd")
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), *from); err != nil {
		fmt.Fprintln(os.Stderr, "newrule:", err)
		os.Exit(1)
	}
}

func run(name string, fromDetector bool) error {
	if err := checkName(name); err != nil {
		return err
	}
	if _, err := os.Stat(builtinDir); err != nil {
		return fmt.Errorf("%s not found: run this from the repository root", builtinDir)
	}

	// The rule is named after the provider, and so is its file, lowercased.
	path := filepath.Join(builtinDir, strings.ToLower(name)+".go")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}

	found := &extracted{Headers: map[string]string{}}
	if fromDetector {
		var err error
		if found, err = readDetector(name); err != nil {
			return err
		}
	}

	source, err := render(name, found)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, source, 0o644); err != nil {
		return err
	}

	report(path, name, found)
	return nil
}

// readDetector finds the hand-written detector for this type and reads what it
// can. A detector that is not there is not an error: the point of the command
// is to save typing where a detector exists, and there is still a skeleton to
// write where one does not.
func readDetector(name string) (*extracted, error) {
	dir, err := findDetector(name)
	if err != nil {
		return nil, err
	}
	if dir == "" {
		fmt.Printf("warning: no detector reports DetectorType_%s, so nothing was imported\n\n", name)
		return &extracted{Headers: map[string]string{}}, nil
	}
	found, err := extractFrom(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	found.Package = dir
	return found, nil
}

// report prints where the file went, what was read, and what was not.
func report(path, name string, found *extracted) {
	fmt.Printf("wrote %s\n", path)
	if found.Package != "" {
		fmt.Printf("imported from %s\n", found.Package)
	}

	if len(found.Notes) > 0 {
		fmt.Println("\nNot imported:")
		for _, note := range found.Notes {
			fmt.Println("  -", note)
		}
	}

	fmt.Println("\nNext:")
	steps := []string{
		"fill in every TODO (see pkg/rules/docs/how-to-add-a-rule.md)",
		"add " + name + " to All in " + builtinDir + "/builtin.go",
		"go test ./pkg/rules/...",
		"go test ./pkg/rules/builtin/test -run TestFindingIdentities -update",
	}
	if found.Package != "" {
		// Reading these correctly is the difference between a rule that works
		// and one that quietly orphans everything already stored.
		steps = append([]string{
			"check SecretID and FullSecretID against Raw and RawV2 in " + found.Package,
		}, steps...)
	} else {
		steps = append(steps[:1], append([]string{
			"add DetectorType_" + name + " to the protobuf enum if it is not there yet",
		}, steps[1:]...)...)
	}
	for _, step := range steps {
		fmt.Println("  -", step)
	}
}

// checkName rejects anything that would not work as a Go identifier or as the
// name of the detector type, which is the same word.
func checkName(name string) error {
	if name == "" {
		return fmt.Errorf("the rule needs a name")
	}
	for i, c := range name {
		if i == 0 && !unicode.IsUpper(c) {
			return fmt.Errorf("%q must start with a capital letter, since the rule is an exported variable", name)
		}
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return fmt.Errorf("%q must be letters and digits only", name)
		}
	}
	return nil
}

// render builds the rule file. Everything the extractor did not find comes out
// as a TODO, which is the same thing the plain skeleton produces, so there is
// one template rather than two.
func render(name string, found *extracted) ([]byte, error) {
	keyword := strings.ToLower(name)
	if len(found.Keywords) > 0 {
		keyword = found.Keywords[0]
	}
	patterns := found.Patterns
	if len(patterns) == 0 {
		patterns = []extractedPattern{{Name: "key", Regex: todo, Prefix: []string{keyword}}}
	}

	data := map[string]any{
		"Name":          name,
		"Keywords":      or(found.Keywords, []string{keyword}),
		"Description":   or(found.Description, todo),
		"Patterns":      patterns,
		"MultiPattern":  len(patterns) > 1,
		"SecretID":      found.SecretID,
		"FullSecretID":  found.FullSecretID,
		"Method":        found.Method,
		"URL":           or(found.URL, todo),
		"Headers":       found.Headers,
		"BasicUser":     found.BasicUser,
		"BasicPass":     found.BasicPass,
		"ValidStatus":   statusCodes(found.ValidStatus, 200),
		"InvalidStatus": statusCodes(found.InvalidStatus, 401),
	}

	var out strings.Builder
	if err := skeleton.Execute(&out, data); err != nil {
		return nil, err
	}
	source, err := format.Source([]byte(out.String()))
	if err != nil {
		return nil, fmt.Errorf("formatting the generated file: %w", err)
	}
	return source, nil
}

func or[T any](value any, fallback T) any {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return fallback
		}
	case []string:
		if len(typed) == 0 {
			return fallback
		}
	}
	return value
}

// statusNumbers covers the codes a verification endpoint actually answers
// with. A name outside it is left as it stands so it is visible rather than
// dropped.
var statusNumbers = map[string]int{
	"StatusOK": 200, "StatusCreated": 201, "StatusAccepted": 202, "StatusNoContent": 204,
	"StatusMovedPermanently": 301, "StatusFound": 302, "StatusNotModified": 304,
	"StatusBadRequest": 400, "StatusUnauthorized": 401, "StatusPaymentRequired": 402,
	"StatusForbidden": 403, "StatusNotFound": 404, "StatusMethodNotAllowed": 405,
	"StatusNotAcceptable": 406, "StatusConflict": 409, "StatusGone": 410,
	"StatusUnprocessableEntity": 422, "StatusTooManyRequests": 429,
	"StatusInternalServerError": 500, "StatusNotImplemented": 501,
	"StatusBadGateway": 502, "StatusServiceUnavailable": 503,
}

// statusCodes turns what the detector compared against into plain numbers,
// which is how a rule lists them.
func statusCodes(names []string, fallback int) []int {
	if len(names) == 0 {
		return []int{fallback}
	}
	var codes []int
	for _, name := range names {
		if code, ok := statusNumbers[name]; ok {
			codes = append(codes, code)
			continue
		}
		if code, err := strconv.Atoi(name); err == nil {
			codes = append(codes, code)
		}
	}
	if len(codes) == 0 {
		return []int{fallback}
	}
	return codes
}

var skeleton = template.Must(template.New("rule").Funcs(template.FuncMap{
	"quote":  strconv.Quote,
	"quotes": quoteAll,
	"raw":    rawString,
	"ints":   joinInts,
}).Parse(`package builtin

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/rules"
)

// TODO: one sentence on what this credential is, plus anything surprising
// about how it is found or verified.
var {{.Name}} = rules.Rule{
	Type: detector_typepb.DetectorType_{{.Name}},

	// The engine does not open a chunk for this rule unless one of these words
	// is in it. Two characters minimum, matched without case.
	Keywords: []string{ {{quotes .Keywords}} },

	// Shown to the user with the finding.
	Description: {{quote .Description}},

	// One entry per part of the credential. Every one of them must match or
	// the rule reports nothing, so put the pickiest pattern first.
	//
	// Prefix requires one of those words shortly before the value. Every word
	// in it must also be a keyword, and the regex then needs a capture group,
	// or the captured value would start at the keyword.
	Patterns: []rules.Pattern{
{{- range .Patterns}}
		{Name: {{quote .Name}}, Regex: {{raw .Regex}}{{if .Prefix}}, Prefix: []string{ {{quotes .Prefix}} }{{end}}},
{{- end}}
	},

{{if .MultiPattern}}	// SecretID is this detector's Raw and FullSecretID its RawV2. Both are
	// hashed into the identifier a finding is stored under, so changing either
	// one makes every finding already stored unreachable. Check them against
	// the detector before trusting them.
	SecretID:     {{if .SecretID}}{{quote .SecretID}}{{else}}"TODO"{{end}},
	FullSecretID: {{if .FullSecretID}}{{quote .FullSecretID}}{{else}}""{{end}},
{{else}}	// A single-pattern rule fills SecretID in on its own. Set FullSecretID
	// only if the detector this replaces sets RawV2.
{{if .FullSecretID}}	FullSecretID: {{quote .FullSecretID}},
{{end}}{{end}}
	Test: rules.Test{
		Detection: rules.DetectionTest{
			// One obviously fake value per pattern. Together they have to look
			// like one whole credential, because the tests build text from
			// them and expect the rule to find exactly these.
			Examples: map[string]string{
{{- range .Patterns}}
				{{quote .Name}}: "TODO",
{{- end}}
			},

			// Values the pattern must refuse. Write each one character off the
			// boundary: a value far outside the pattern still passes after
			// someone loosens the regex by mistake, which is the bug these
			// exist to catch.
			NotExamples: map[string][]string{
{{- range .Patterns}}
				{{quote .Name}}: {"TODO"},
{{- end}}
			},
		},

		// Field names in the project's secret manager, never the values. Take
		// them from the hand-written detector's integration test. Delete this
		// block if there is no live test.
		Integration: rules.IntegrationTest{
			Group:   "TODO",
			Valid:   []string{"TODO"},
			Invalid: []string{"TODO_INACTIVE"},
		},
	},

	// One request, and its status decides the answer. List only the codes this
	// provider actually documents: a status in neither set becomes Unknown,
	// which is the honest answer for a response nobody planned for.
	//
	// Use rules.None{} when there is nothing to call, or rules.Func for
	// verification that needs request signing or a connection.
	Verify: rules.HTTP{
{{- if .Method}}{{if ne .Method "GET"}}
		Method: {{quote .Method}},
{{- end}}{{end}}
		URL: {{quote .URL}},
{{- if .Headers}}
		Headers: map[string]string{
{{- range $name, $value := .Headers}}
			{{quote $name}}: {{quote $value}},
{{- end}}
		},
{{- end}}
{{- if .BasicUser}}
		BasicUser: {{quote .BasicUser}},
		BasicPass: {{quote .BasicPass}},
{{- end}}
		ValidStatus:   rules.StatusCodes{ {{ints .ValidStatus}} },
		InvalidStatus: rules.StatusCodes{ {{ints .InvalidStatus}} },
	},

	// The rest are optional. Delete what this rule does not need.
	//
	// Version:           2,    // only when one provider has two live implementations
	// DistinctCaptures:  true, // when two patterns can match each other's values
	// ExtraData:         map[string]string{"rotation_guide": "https://..."},
	// MaxCredentialSpan: 4096, // default is 10KB, or 1MB with two or more patterns
	// Disabled:          true, // takes the provider out of the scan completely
}
`))

func quoteAll(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, strconv.Quote(value))
	}
	return strings.Join(quoted, ", ")
}

func joinInts(values []int) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strconv.Itoa(value))
	}
	return strings.Join(out, ", ")
}

// rawString writes a regex as a backquoted literal, which is how a rule reads
// best. A regex holding a backquote cannot be written that way, so it falls
// back to a quoted string.
func rawString(value string) string {
	if strings.Contains(value, "`") {
		return strconv.Quote(value)
	}
	return "`" + value + "`"
}
