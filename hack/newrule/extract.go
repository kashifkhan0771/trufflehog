package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// detectorsDir is where the hand-written detectors live. It is a variable so
// the tests can point at the same tree from their own directory.
var detectorsDir = "pkg/detectors"

// extracted is what could be read out of a hand-written detector. Every field
// is optional: the renderer leaves a TODO wherever one is empty, so a detector
// written in a shape this does not understand still produces a usable file.
type extracted struct {
	Package     string
	Keywords    []string
	Description string
	Patterns    []extractedPattern

	Method    string
	URL       string
	Headers   map[string]string
	BasicUser string
	BasicPass string

	ValidStatus   []string
	InvalidStatus []string

	SecretID     string
	FullSecretID string

	// consts holds package-level string constants and variables, so a URL or
	// header built from one can be resolved. Detectors commonly keep the base
	// URL in a const and add the path at the call.
	consts map[string]string

	// Notes say what was not taken and why. They are printed after the file is
	// written, so nothing looks filled in when it was skipped.
	Notes []string
}

type extractedPattern struct {
	Name   string
	Regex  string
	Prefix []string
}

func (e *extracted) note(format string, args ...any) {
	e.Notes = append(e.Notes, fmt.Sprintf(format, args...))
}

// findDetector returns the directory of the detector package whose Type()
// reports this detector type, or "" when no package does.
//
// It searches by what a detector says it is rather than by directory name,
// because the two often differ: a detector can sit under a vendor folder, or
// in a version subdirectory.
func findDetector(name string) (string, error) {
	needle := []byte("DetectorType_" + name)
	var found []string

	err := filepath.WalkDir(detectorsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Cheap filter first: reading 886 packages is worth avoiding, and a
		// detector always names its own type in its Type method.
		source, err := os.ReadFile(path)
		if err != nil || !containsWord(source, needle) {
			return nil
		}
		if declaresType(path, name) {
			found = append(found, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(found) == 0 {
		return "", nil
	}
	sort.Strings(found)
	return found[0], nil
}

// containsWord reports whether needle appears in source without a letter or
// digit straight after it, so DetectorType_Box does not match
// DetectorType_BoxOauth.
func containsWord(source, needle []byte) bool {
	for i := 0; ; {
		at := strings.Index(string(source[i:]), string(needle))
		if at < 0 {
			return false
		}
		end := i + at + len(needle)
		if end >= len(source) || !isIdentByte(source[end]) {
			return true
		}
		i = end
	}
}

func isIdentByte(c byte) bool {
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9')
}

// declaresType reports whether the file has a Type method returning this
// detector type, which is what makes the package that detector rather than one
// merely mentioning it.
func declaresType(path, name string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return false
	}
	declares := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Type" || fn.Recv == nil || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if selector, ok := n.(*ast.SelectorExpr); ok && selector.Sel.Name == "DetectorType_"+name {
				declares = true
			}
			return true
		})
	}
	return declares
}

// extractFrom reads everything it understands out of a detector package.
func extractFrom(dir string) (*extracted, error) {
	files, err := parseDir(dir)
	if err != nil {
		return nil, err
	}

	out := &extracted{Headers: map[string]string{}, consts: map[string]string{}}
	if len(files) > 0 {
		out.Package = files[0].Name.Name
	}
	// Constants first: a later file may use one declared in an earlier.
	for _, file := range files {
		out.readConstants(file)
	}
	for _, file := range files {
		out.readFile(file)
	}
	sort.Slice(out.Patterns, func(i, j int) bool { return out.Patterns[i].Name < out.Patterns[j].Name })

	// A detector whose success depends on the response body, not the status
	// alone, leaves nothing to read for the valid case. That is a real thing a
	// rule can say, so point at the field that says it.
	if len(out.ValidStatus) == 0 && len(out.InvalidStatus) > 0 {
		out.note("the valid outcome depends on more than the status code; see HTTP.ValidBodyContains")
	}
	return out, nil
}

// parseDir parses every non-test .go file directly in dir, skipping
// subdirectories.
//
// This is deliberately not parser.ParseDir: that function is deprecated
// because it groups files into packages without knowing about build tags,
// which does not matter here - a detector package has exactly one build
// configuration - but it is one file fewer to carry a deprecated call for.
func parseDir(dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fileSet := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

// readConstants collects every package-level string constant and variable.
func (e *extracted) readConstants(file *ast.File) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				if text, ok := stringValue(value.Values[i]); ok {
					e.consts[name.Name] = text
				}
			}
		}
	}
}

// text resolves an expression to a string: a literal, a package-level constant,
// or the two joined. A format string is taken as it stands, since the parts it
// fills in are values only the author can name.
func (e *extracted) text(expr ast.Expr) (string, bool) {
	switch typed := expr.(type) {
	case *ast.BasicLit:
		return stringValue(expr)
	case *ast.Ident:
		value, ok := e.consts[typed.Name]
		return value, ok
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", false
		}
		left, leftOK := e.text(typed.X)
		right, rightOK := e.text(typed.Y)
		if !leftOK || !rightOK {
			return "", false
		}
		return left + right, true
	case *ast.CallExpr:
		// fmt.Sprintf("https://api.example.com/v1/%s", id)
		if isSelector(typed.Fun, "fmt", "Sprintf") && len(typed.Args) > 0 {
			if format, ok := stringValue(typed.Args[0]); ok {
				return format, true
			}
		}
	}
	return "", false
}

func (e *extracted) readFile(file *ast.File) {
	for _, decl := range file.Decls {
		switch typed := decl.(type) {
		case *ast.GenDecl:
			e.readVars(typed)
		case *ast.FuncDecl:
			e.readFunc(typed)
		}
	}
}

// readVars picks up the package-level regex variables, which is where a
// detector keeps its patterns.
func (e *extracted) readVars(decl *ast.GenDecl) {
	if decl.Tok != token.VAR {
		return
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range value.Names {
			if i >= len(value.Values) {
				continue
			}
			if count, ok := regexMapSize(value.Values[i]); ok {
				// A handful of detectors hold several regexes that are
				// alternatives for the same credential. A rule cannot say that:
				// every pattern it lists must match. So say what was found and
				// leave the choice to the author.
				e.note("%s holds %d alternative regexes; a rule needs every pattern to match, "+
					"so combine them into one regex with | or write one rule per shape", name.Name, count)
				continue
			}
			call, ok := value.Values[i].(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, "regexp", "MustCompile") || len(call.Args) != 1 {
				continue
			}
			pattern := extractedPattern{Name: patternName(name.Name)}
			regex, prefix, ok := regexParts(call.Args[0])
			if !ok {
				e.note("pattern %q is built in a way this does not read; its regex is a TODO", pattern.Name)
				continue
			}
			pattern.Regex, pattern.Prefix = regex, prefix
			e.Patterns = append(e.Patterns, pattern)
		}
	}
}

// regexMapSize reports how many regexes a map of them holds, for the detectors
// that keep alternatives rather than parts.
func regexMapSize(expr ast.Expr) (int, bool) {
	literal, ok := expr.(*ast.CompositeLit)
	if !ok {
		return 0, false
	}
	mapType, ok := literal.Type.(*ast.MapType)
	if !ok {
		return 0, false
	}
	star, ok := mapType.Value.(*ast.StarExpr)
	if !ok || !isSelector(star.X, "regexp", "Regexp") {
		return 0, false
	}
	return len(literal.Elts), true
}

// patternName turns a variable name into a capture name: keyPat becomes key,
// idPattern becomes id. Anything else is used as it stands.
func patternName(variable string) string {
	for _, suffix := range []string{"Pattern", "Pat", "Regex", "Re"} {
		if trimmed := strings.TrimSuffix(variable, suffix); trimmed != variable && trimmed != "" {
			variable = trimmed
			break
		}
	}
	return strings.ToLower(variable[:1]) + variable[1:]
}

// regexParts reads the expression a detector builds its regex from. Two shapes
// are understood: a plain string, and a keyword prefix added to one. Anything
// else, such as a regex assembled from several helpers, is refused rather than
// half-read.
func regexParts(expr ast.Expr) (regex string, prefix []string, ok bool) {
	switch typed := expr.(type) {
	case *ast.BasicLit:
		value, err := strconv.Unquote(typed.Value)
		return value, nil, err == nil

	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", nil, false
		}
		// The prefix, when there is one, always comes first.
		if words, isPrefix := prefixWords(typed.X); isPrefix {
			rest, nested, ok := regexParts(typed.Y)
			if !ok || len(nested) > 0 {
				return "", nil, false
			}
			return rest, words, true
		}
		left, leftPrefix, leftOK := regexParts(typed.X)
		right, rightPrefix, rightOK := regexParts(typed.Y)
		if !leftOK || !rightOK || len(leftPrefix) > 0 || len(rightPrefix) > 0 {
			return "", nil, false
		}
		return left + right, nil, true
	}
	return "", nil, false
}

// prefixWords reads the keyword list out of detectors.PrefixRegex([]string{...}).
func prefixWords(expr ast.Expr) ([]string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || !isSelector(call.Fun, "detectors", "PrefixRegex") || len(call.Args) != 1 {
		return nil, false
	}
	literal, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	return stringList(literal), true
}

func (e *extracted) readFunc(fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	switch fn.Name.Name {
	case "Keywords":
		e.Keywords = firstStringList(fn.Body)
	case "Description":
		e.Description = firstString(fn.Body)
	}

	// The request and the result can be anywhere: some detectors verify in a
	// function of their own, others inline in FromData. Walking every function
	// body means the shape does not matter.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch typed := n.(type) {
		case *ast.CallExpr:
			e.readCall(typed)
		case *ast.CompositeLit:
			e.readResult(typed)
		case *ast.SwitchStmt:
			e.readStatusSwitch(typed)
		case *ast.IfStmt:
			e.readStatusIf(typed)
		}
		return true
	})
}

// readCall picks the request out of whatever function builds it.
func (e *extracted) readCall(call *ast.CallExpr) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	switch selector.Sel.Name {
	case "NewRequestWithContext", "NewRequest":
		// NewRequest has no context argument, so the method and URL sit one
		// place earlier.
		args := call.Args
		if selector.Sel.Name == "NewRequestWithContext" {
			if len(args) < 3 {
				return
			}
			args = args[1:]
		}
		if len(args) < 2 {
			return
		}
		if method, ok := stringValue(args[0]); ok {
			e.Method = method
		} else if method, ok := statusName(args[0]); ok {
			// http.MethodGet and friends.
			e.Method = strings.ToUpper(strings.TrimPrefix(method, "Method"))
		}
		if url, ok := e.text(args[1]); ok {
			e.URL = url
			if strings.Contains(url, "%") {
				e.note("the verification URL fills in a value at run time; replace each verb with a {name} placeholder")
			}
		} else {
			e.note("the verification URL is built in a way this does not read; URL is a TODO")
		}

	case "Add", "Set":
		// Only header calls, not map or url.Values writes.
		if !isHeaderTarget(selector.X) || len(call.Args) != 2 {
			return
		}
		name, ok := stringValue(call.Args[0])
		if !ok {
			return
		}
		if value, ok := e.text(call.Args[1]); ok {
			e.Headers[name] = value
			return
		}
		e.Headers[name] = todo
		e.note("header %q holds a captured value; fill in its template", name)

	case "SetBasicAuth":
		if len(call.Args) != 2 {
			return
		}
		e.BasicUser = e.basicAuthPart(call.Args[0])
		e.BasicPass = e.basicAuthPart(call.Args[1])
	}
}

// basicAuthPart keeps a literal as it stands and marks anything else, since a
// variable here is a captured value whose name only the author knows.
func (e *extracted) basicAuthPart(expr ast.Expr) string {
	if value, ok := e.text(expr); ok {
		return value
	}
	return todo
}

func isHeaderTarget(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Header"
}

// readResult reads a detectors.Result literal. SecretParts names each captured
// value, which is what makes Raw and RawV2 readable: without it a variable in
// Raw could not be tied back to a pattern.
func (e *extracted) readResult(literal *ast.CompositeLit) {
	if !isSelector(literal.Type, "detectors", "Result") {
		return
	}
	fields := map[string]ast.Expr{}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := pair.Key.(*ast.Ident); ok {
			fields[key.Name] = pair.Value
		}
	}

	names := secretPartNames(fields["SecretParts"])
	if len(names) == 0 {
		e.note("the detector does not name its captured values, so SecretID and FullSecretID are TODOs")
		return
	}
	if identity, ok := identityTemplate(fields["Raw"], names); ok {
		e.SecretID = identity
	} else if fields["Raw"] != nil {
		e.note("Raw is built in a way this does not read; SecretID is a TODO")
	}
	if identity, ok := identityTemplate(fields["RawV2"], names); ok {
		e.FullSecretID = identity
	} else if fields["RawV2"] != nil {
		e.note("RawV2 is built in a way this does not read; FullSecretID is a TODO")
	}
}

// secretPartNames maps each variable to the name the detector stored it under.
func secretPartNames(expr ast.Expr) map[string]string {
	literal, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	names := map[string]string{}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name, ok := stringValue(pair.Key)
		if !ok {
			continue
		}
		if ident, ok := pair.Value.(*ast.Ident); ok {
			names[ident.Name] = name
		}
	}
	return names
}

// identityTemplate turns []byte(a) or []byte(a + b) into "{key}" or "{key}{id}",
// using the names the detector gave those variables. Anything else is refused:
// these two fields are hashed into the identifier a finding is stored under, so
// a wrong guess strands what is already stored.
func identityTemplate(expr ast.Expr, names map[string]string) (string, bool) {
	if expr == nil {
		return "", false
	}
	// Unwrap the []byte(...) conversion.
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if array, ok := call.Fun.(*ast.ArrayType); ok {
			if ident, ok := array.Elt.(*ast.Ident); ok && ident.Name == "byte" {
				expr = call.Args[0]
			}
		}
	}
	switch typed := expr.(type) {
	case *ast.Ident:
		name, ok := names[typed.Name]
		if !ok {
			return "", false
		}
		return "{" + name + "}", true
	case *ast.BinaryExpr:
		if typed.Op != token.ADD {
			return "", false
		}
		left, leftOK := identityTemplate(typed.X, names)
		right, rightOK := identityTemplate(typed.Y, names)
		if !leftOK || !rightOK {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// readStatusSwitch reads the common shape: switch on the response status, one
// case per outcome.
func (e *extracted) readStatusSwitch(stmt *ast.SwitchStmt) {
	if !isStatusCode(stmt.Tag) {
		return
	}
	for _, item := range stmt.Body.List {
		clause, ok := item.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 {
			continue
		}
		verified, known := verdictOf(clause.Body)
		if !known {
			continue
		}
		for _, expr := range clause.List {
			e.addStatus(expr, verified)
		}
	}
}

// readStatusIf reads the other common shape: if the status equals this, the
// credential is good.
func (e *extracted) readStatusIf(stmt *ast.IfStmt) {
	comparison, ok := stmt.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return
	}
	var status ast.Expr
	switch {
	case isStatusCode(comparison.X):
		status = comparison.Y
	case isStatusCode(comparison.Y):
		status = comparison.X
	default:
		return
	}
	if verified, known := verdictOf(stmt.Body.List); known {
		e.addStatus(status, verified)
	}
}

func (e *extracted) addStatus(expr ast.Expr, verified bool) {
	name, ok := statusName(expr)
	if !ok {
		if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.INT {
			name = literal.Value
		} else {
			return
		}
	}
	list := &e.InvalidStatus
	if verified {
		list = &e.ValidStatus
	}
	for _, existing := range *list {
		if existing == name {
			return
		}
	}
	*list = append(*list, name)
}

// verdictOf reads what a branch decided. A detector reports verification as a
// bool, so "return true" means the provider accepted the credential and
// "return false, nil" means it rejected it. A branch returning an error decided
// nothing, which is Unknown, and Unknown is not listed on a rule.
func verdictOf(body []ast.Stmt) (verified, known bool) {
	for _, stmt := range body {
		switch typed := stmt.(type) {
		case *ast.ReturnStmt:
			return boolResult(typed.Results)
		case *ast.AssignStmt:
			// Inline verification writes to the result instead of returning.
			for i, target := range typed.Lhs {
				selector, ok := target.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Verified" || i >= len(typed.Rhs) {
					continue
				}
				if ident, ok := typed.Rhs[i].(*ast.Ident); ok {
					return ident.Name == "true", ident.Name == "true" || ident.Name == "false"
				}
			}
		}
	}
	return false, false
}

func boolResult(results []ast.Expr) (verified, known bool) {
	if len(results) == 0 {
		return false, false
	}
	ident, ok := results[0].(*ast.Ident)
	if !ok {
		return false, false
	}
	if ident.Name == "true" {
		return true, true
	}
	if ident.Name != "false" {
		return false, false
	}
	// A false with an error attached is an attempt that failed, not a
	// rejection, so it says nothing about the status code.
	for _, rest := range results[1:] {
		if ident, ok := rest.(*ast.Ident); !ok || ident.Name != "nil" {
			return false, false
		}
	}
	return false, true
}

func isStatusCode(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "StatusCode"
}

// statusName returns the name of an http.Status constant, such as StatusOK.
func statusName(expr ast.Expr) (string, bool) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "http" {
		return "", false
	}
	return selector.Sel.Name, true
}

func isSelector(expr ast.Expr, pkg, name string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	ident, ok := selector.X.(*ast.Ident)
	return ok && ident.Name == pkg
}

func stringValue(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

// firstString returns the first string literal returned by a function body,
// joining a concatenation, which is how long descriptions are written.
func firstString(body *ast.BlockStmt) string {
	var found string
	ast.Inspect(body, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		stmt, ok := n.(*ast.ReturnStmt)
		if !ok || len(stmt.Results) == 0 {
			return true
		}
		found = joinStrings(stmt.Results[0])
		return true
	})
	return found
}

func joinStrings(expr ast.Expr) string {
	if value, ok := stringValue(expr); ok {
		return value
	}
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op != token.ADD {
		return ""
	}
	left, right := joinStrings(binary.X), joinStrings(binary.Y)
	if left == "" || right == "" {
		return ""
	}
	return left + right
}

func firstStringList(body *ast.BlockStmt) []string {
	var found []string
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		if literal, ok := n.(*ast.CompositeLit); ok {
			found = stringList(literal)
		}
		return true
	})
	return found
}

func stringList(literal *ast.CompositeLit) []string {
	var values []string
	for _, element := range literal.Elts {
		if value, ok := stringValue(element); ok {
			values = append(values, value)
		}
	}
	return values
}
