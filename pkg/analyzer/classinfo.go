package analyzer

import (
	"regexp"
	"sort"
	"strings"
)

// PHP has four kinds of type declaration with a braced body -- class, trait,
// interface and enum -- and a method declared in any of them belongs to that
// type rather than to the global namespace. The call graph recognised only
// `class`, so every method declared in a trait was attributed to no type at
// all, stored under its bare name, and left to collide with every other
// declaration of that name in the plugin. Measured over a 143-plugin corpus:
// 765 trait declarations in 60 trees holding 3,707 methods, of which 1,165
// (31.4%) share a bare name with a non-trait declaration in the same tree and
// therefore resolved to an unrelated body.
//
// The `extends` and `implements` clauses were rejected outright when the parent
// was written with a leading backslash, which is PHP's ordinary spelling for a
// global-namespace name inside a namespaced file: `class Table extends
// \WP_List_Table {`. Both optional groups required the name to start with a
// letter, so the leading "\" made the group fail and the trailing `\s*\{` then
// had nothing to match. That hid 4,936 class declarations in 82 trees and the
// 30,637 method declarations inside them -- 9.6% of every declaration in the
// corpus, and 39.4% of wpforms-lite's.
//
// `\Foo\Bar` is the fully-qualified form of `Foo\Bar`; the leading backslash is
// name-resolution syntax and carries no meaning for identifying the parent. Any
// pattern that accepts `extends Foo` must accept `extends \Foo` or it is
// rejecting valid PHP.
//
// The keyword alternation is deliberately NON-capturing so that capture group 1
// remains the declared name. Every consumer of this pattern reads the name out
// of group 1; making the keyword a group would silently key every type in every
// plugin as "class".
//
// The leading anchor is "start of line, or after a token that can legally
// precede a declaration" rather than the old `^[\t ]*`. A declaration sharing a
// line with something else -- `<?php class Loader {`, or two on one line -- was
// invisible under the old anchor, which is the same relaxation
// FindFunctionDeclarations already needed.
var classDeclPattern = regexp.MustCompile(
	`(?m)(?:^|[\s;{}])(?:(?:abstract|final|readonly)\s+)*(?:class|trait|interface|enum)\s+` +
		`([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)` +
		// A backed enum names its scalar type: `enum Suit: string {`.
		`(?:\s*:\s*\\?[a-zA-Z_][a-zA-Z0-9_\\]*)?` +
		// `extends` takes a list, because an interface may extend several.
		`(?:\s+extends\s+(\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*` +
		`(?:\s*,\s*\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*)*))?` +
		`(?:\s+implements\s+(\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\,\s]*))?` +
		`\s*\{`)

// classDefPattern is retained under its old name because the widened pattern is
// a drop-in replacement: the keyword alternation is non-capturing, so group 1
// is still the declared name and every existing consumer keeps working.
var classDefPattern = classDeclPattern

// traitUsePattern finds `use T;`, `use A, B;` and `use T { ... }` inside a type
// body.
//
// The previous pattern required `(?m)^\s+use` and an upper-case initial. PHP
// has no capitalisation rule for type names -- 1,305 lower-case classes across
// 51 corpus trees make that concrete -- and a body written on one line,
// `class X { use T; }`, has no whitespace-led `use` at all. The leading
// backslash of a fully-qualified trait name was rejected for the same reason
// the extends clause was.
//
// This pattern is only ever run over the inside of a type body, so a file-scope
// `use Foo\Bar;` import cannot be mistaken for a trait use. A closure's
// `use ($x)` clause is excluded because "$" is not a name character.
var traitUsePattern = regexp.MustCompile(
	`(?:^|[\s{;])use\s+(\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*` +
		`(?:\s*,\s*\\?[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*)*)\s*[;{]`)

// useAliasPattern finds a file-scope import that renames what it imports:
//
//	use Vendor\Package\Zip as ArchiveWriter;
//
// PHP scopes such an alias to the file it is written in, which is why the map
// it fills is per-file and never global.
var useAliasPattern = regexp.MustCompile(
	`(?m)^[\t ]*use\s+(?:function\s+)?\\?([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\\]*)\s+as\s+` +
		`([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)\s*;`)

// classInfo is one PHP type declaration as the call graph needs to see it.
type classInfo struct {
	// Name is the declared name, without any namespace prefix.
	Name string
	// Kind is "class", "trait", "interface" or "enum".
	Kind string
	// Parent is the last segment of the first `extends` target, or "" when the
	// type extends nothing. PHP resolves `parent::m()` against it.
	Parent string
	// Traits are the names given by `use T;` inside the body, in declaration
	// order -- the order PHP itself consults them when resolving a method.
	Traits []string
	// Open is the offset of the body's "{"; Close is one past its "}".
	Open, Close int
}

// findClassInfos returns every type declared in content, keyed by name.
func findClassInfos(content string) map[string]classInfo {
	matches := classDeclPattern.FindAllStringSubmatchIndex(content, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make(map[string]classInfo, len(matches))
	for _, m := range matches {
		if len(m) < 4 || m[2] < 0 {
			continue
		}
		name := content[m[2]:m[3]]

		// The pattern ends with `\s*\{`, so the match already consumes the
		// body's opening brace and m[1]-1 is its offset. Searching forward for
		// the next "{" instead finds the first METHOD's brace, which is how
		// every recorded range once came to be one method body.
		openBrace := m[1] - 1
		if openBrace < 0 || openBrace >= len(content) || content[openBrace] != '{' {
			continue
		}
		closeBrace := findMatchingBrace(content, openBrace)
		if closeBrace < 0 {
			continue
		}

		ci := classInfo{
			Name:  name,
			Kind:  declKeyword(content[m[0]:m[2]]),
			Open:  openBrace,
			Close: closeBrace,
		}
		if len(m) >= 6 && m[4] >= 0 {
			ci.Parent = lastNameSegment(firstListItem(content[m[4]:m[5]]))
		}
		ci.Traits = traitsUsedIn(content[openBrace:closeBrace])
		out[name] = ci
	}
	return out
}

// declKeyword reads the kind out of the text between the start of a type
// declaration and its name, which holds the modifiers and the keyword.
func declKeyword(head string) string {
	for _, kw := range [4]string{"class", "trait", "interface", "enum"} {
		if idx := strings.LastIndex(head, kw); idx >= 0 {
			// "interface" contains no other keyword, but "class" is a substring
			// of nothing here and the scan is ordered so the longest sensible
			// match is taken by checking the tail of the head text.
			if isWordBoundedAt(head, idx, len(kw)) {
				return kw
			}
		}
	}
	return "class"
}

func isWordBoundedAt(s string, at, n int) bool {
	if at > 0 && isTypeChar(s[at-1]) {
		return false
	}
	end := at + n
	return end >= len(s) || !isTypeChar(s[end])
}

// firstListItem takes the first entry of a comma-separated `extends` clause.
// A class extends exactly one parent; an interface may extend several, and the
// first is the one `parent::` would name if the construct were a class.
func firstListItem(list string) string {
	if i := strings.IndexByte(list, ','); i >= 0 {
		list = list[:i]
	}
	return strings.TrimSpace(list)
}

// lastNameSegment reduces a possibly-qualified PHP name to its final segment.
// The call graph keys types by their declared (unqualified) name, and
// `\Vendor\Package\Base` and `Base` denote the same declaration for that
// purpose.
func lastNameSegment(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimPrefix(name, "\\")
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// traitsUsedIn lists the traits a type body imports, in declaration order.
func traitsUsedIn(body string) []string {
	matches := traitUsePattern.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil
	}
	var out []string
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		for _, part := range strings.Split(m[1], ",") {
			t := lastNameSegment(part)
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// fileUseAliases returns the file-scoped `use X as Y` renames in content, as
// alias -> the last segment of the imported name.
func fileUseAliases(content string) map[string]string {
	matches := useAliasPattern.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make(map[string]string, len(matches))
	for _, m := range matches {
		target := lastNameSegment(m[1])
		if target == "" || target == m[2] {
			continue
		}
		out[m[2]] = target
	}
	return out
}

// enclosingType returns the innermost type declaration containing pos.
//
// Innermost means smallest range: a declaration can sit inside only one type in
// PHP, but a file's ranges are held in a map, and picking whichever the map
// iteration reached first made the answer depend on hash order.
func enclosingType(pos int, infos map[string]classInfo) *classInfo {
	var best *classInfo
	bestSize := int(^uint(0) >> 1)
	for name := range infos {
		ci := infos[name]
		if pos > ci.Open && pos < ci.Close {
			if size := ci.Close - ci.Open; size < bestSize {
				bestSize = size
				c := ci
				best = &c
			}
		}
	}
	return best
}

// TypeDef is what the whole plugin knows about one declared type name, merged
// over every file that declares it.
type TypeDef struct {
	Name string
	// Kind is the kind of the FIRST declaration seen in sorted file order.
	Kind string
	// Parent is the first non-empty `extends` target seen.
	Parent string
	// Traits is the union of the traits every declaration of this name uses.
	Traits []string
	// Methods is the union of the method names every declaration of this name
	// declares, sorted.
	Methods []string
	// Files lists every file declaring this name, in sorted order.
	Files []string
}

// addMethods merges declared method names into the type, keeping the list
// sorted and free of duplicates so the graph is reproducible run to run.
func (t *TypeDef) addMethods(names []string) {
	for _, n := range names {
		i := sort.SearchStrings(t.Methods, n)
		if i < len(t.Methods) && t.Methods[i] == n {
			continue
		}
		t.Methods = append(t.Methods, "")
		copy(t.Methods[i+1:], t.Methods[i:])
		t.Methods[i] = n
	}
}
