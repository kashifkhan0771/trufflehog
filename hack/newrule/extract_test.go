package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The tests run from this directory, while the tool runs from the repository
// root, so point the extractor at the same tree from here.
func init() { detectorsDir = filepath.Join("..", "..", "pkg", "detectors") }

// TestExtractKnownDetectors pins what comes out of detectors of different
// shapes: basic auth against a bearer header, one pattern against two, a
// switch on the status against an if, a RawV2 against none.
func TestExtractKnownDetectors(t *testing.T) {
	cases := []struct {
		detector     string
		keywords     []string
		patterns     []string
		regexes      []string
		prefix       []string
		url          string
		validStatus  []string
		invalidStat  []string
		basicUser    string
		basicPass    string
		secretID     string
		fullSecretID string
	}{
		{
			detector:    "Bugherd",
			keywords:    []string{"bugherd"},
			patterns:    []string{"key"},
			regexes:     []string{`\b([0-9a-z]{22})\b`},
			prefix:      []string{"bugherd"},
			url:         "https://www.bugherd.com/api_v2/projects.json",
			validStatus: []string{"StatusOK"},
			invalidStat: []string{"StatusUnauthorized"},
			basicUser:   todo, // the key, which the detector holds in a variable
			basicPass:   "x",
			secretID:    "{key}",
		},
		{
			detector:     "Aylien",
			keywords:     []string{"aylien"},
			patterns:     []string{"id", "key"},
			regexes:      []string{`\b([a-z0-9]{8})\b`, `\b([a-z0-9]{32})\b`},
			prefix:       []string{"aylien"},
			url:          "https://api.aylien.com/news/stories",
			secretID:     "{key}",
			fullSecretID: "{key}{id}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.detector, func(t *testing.T) {
			dir, err := findDetector(tc.detector)
			if err != nil || dir == "" {
				t.Fatalf("finding the detector: dir=%q err=%v", dir, err)
			}
			found, err := extractFrom(dir)
			if err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(found.Keywords, tc.keywords) {
				t.Errorf("keywords = %v, want %v", found.Keywords, tc.keywords)
			}
			if found.Description == "" {
				t.Error("no description was read")
			}

			var names, regexes []string
			for _, pattern := range found.Patterns {
				names = append(names, pattern.Name)
				regexes = append(regexes, pattern.Regex)
				if tc.prefix != nil && !slices.Equal(pattern.Prefix, tc.prefix) {
					t.Errorf("pattern %q prefix = %v, want %v", pattern.Name, pattern.Prefix, tc.prefix)
				}
			}
			if !slices.Equal(names, tc.patterns) {
				t.Errorf("pattern names = %v, want %v", names, tc.patterns)
			}
			if !slices.Equal(regexes, tc.regexes) {
				t.Errorf("regexes = %v, want %v", regexes, tc.regexes)
			}

			if found.URL != tc.url {
				t.Errorf("URL = %q, want %q", found.URL, tc.url)
			}
			if tc.validStatus != nil && !slices.Equal(found.ValidStatus, tc.validStatus) {
				t.Errorf("ValidStatus = %v, want %v", found.ValidStatus, tc.validStatus)
			}
			if tc.invalidStat != nil && !slices.Equal(found.InvalidStatus, tc.invalidStat) {
				t.Errorf("InvalidStatus = %v, want %v", found.InvalidStatus, tc.invalidStat)
			}
			if found.BasicUser != tc.basicUser || found.BasicPass != tc.basicPass {
				t.Errorf("basic auth = %q/%q, want %q/%q",
					found.BasicUser, found.BasicPass, tc.basicUser, tc.basicPass)
			}
			if found.SecretID != tc.secretID {
				t.Errorf("SecretID = %q, want %q", found.SecretID, tc.secretID)
			}
			if found.FullSecretID != tc.fullSecretID {
				t.Errorf("FullSecretID = %q, want %q", found.FullSecretID, tc.fullSecretID)
			}
		})
	}
}

// TestExtractRendersValidGo checks the whole path for every detector: read it,
// render the file, and hand the result to gofmt. A shape the extractor
// misreads must still produce a file that parses, since the point of the tool
// is a starting point, not a finished rule.
//
// It also reports how much was read across the whole set, which is the only
// honest answer to "does this work for all of them".
func TestExtractRendersValidGo(t *testing.T) {
	dirs := detectorDirs(t)
	if len(dirs) < 500 {
		t.Fatalf("only found %d detector packages, expected the whole tree", len(dirs))
	}

	var read struct{ keywords, description, patterns, prefix, url, status, secretID, full int }
	failed := 0

	for _, dir := range dirs {
		found, err := extractFrom(dir)
		if err != nil {
			// A package that does not parse is not this tool's problem.
			continue
		}
		if _, err := render("Example", found); err != nil {
			failed++
			t.Errorf("%s: rendered file does not compile: %v", dir, err)
			continue
		}

		if len(found.Keywords) > 0 {
			read.keywords++
		}
		if found.Description != "" {
			read.description++
		}
		if len(found.Patterns) > 0 {
			read.patterns++
		}
		if len(found.Patterns) > 0 && len(found.Patterns[0].Prefix) > 0 {
			read.prefix++
		}
		if found.URL != "" {
			read.url++
		}
		if len(found.ValidStatus) > 0 || len(found.InvalidStatus) > 0 {
			read.status++
		}
		if found.SecretID != "" {
			read.secretID++
		}
		if found.FullSecretID != "" {
			read.full++
		}
	}

	total := len(dirs)
	t.Logf("read from %d detector packages:", total)
	for _, line := range []struct {
		what  string
		count int
	}{
		{"keywords", read.keywords},
		{"description", read.description},
		{"patterns", read.patterns},
		{"pattern prefix", read.prefix},
		{"verification URL", read.url},
		{"status codes", read.status},
		{"SecretID", read.secretID},
		{"FullSecretID", read.full},
	} {
		t.Logf("  %-18s %4d  (%d%%)", line.what, line.count, line.count*100/total)
	}

	// Floors, not targets. They are here so a change that quietly stops
	// reading something shows up as a failure rather than as a worse tool.
	//
	// Status codes sit low on purpose. Only about a third of detectors decide
	// on the status alone; the rest read the response body as well, and for
	// those the status says nothing definite. Reading fewer of them is the
	// honest answer, not a gap to close.
	for _, check := range []struct {
		what    string
		count   int
		percent int
	}{
		{"keywords", read.keywords, 90},
		{"patterns", read.patterns, 85},
		{"verification URL", read.url, 65},
		{"status codes", read.status, 25},
		{"SecretID", read.secretID, 60},
	} {
		if got := check.count * 100 / total; got < check.percent {
			t.Errorf("%s read from %d%% of detectors, want at least %d%%", check.what, got, check.percent)
		}
	}
}

// detectorDirs lists every directory holding detector source.
func detectorDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(detectorsDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, file := range entries {
			name := file.Name()
			if !file.IsDir() && filepath.Ext(name) == ".go" && !isTestFile(name) {
				dirs = append(dirs, path)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

func isTestFile(name string) bool {
	return len(name) > 8 && name[len(name)-8:] == "_test.go"
}
