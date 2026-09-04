package analyzer

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	wpast "github.com/hatlesswizard/wptracelib/pkg/ast"
	"github.com/hatlesswizard/wptracelib/pkg/config"
	"github.com/hatlesswizard/wptracelib/pkg/models"
)

var (
	directSuperglobalPattern = regexp.MustCompile(
		`\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[`)

	directPhpInputPattern = regexp.MustCompile(
		`php://input`)

	// directBootstrapGuardPattern is the "this file refuses to run on its own"
	// check: defined('ABSPATH') / defined('WPINC'). A file that opens with it
	// cannot be requested directly, whatever else it contains.
	//
	// It used to have two more branches -- a require of wp-load.php /
	// wp-blog-header.php / wp-config.php, and a require of ABSPATH . '...' --
	// and the first of those is the opposite signal. A file that loads
	// wp-load.php for itself is bootstrapping WordPress because it expects to be
	// requested directly; that is the shape of the whole "direct file access"
	// vulnerability class, not a defence against it. While only the first
	// hundred lines were read the conflation stayed latent, because every file
	// rejected on the wp-load branch also carried a real defined(ABSPATH) guard.
	// Reading the whole file detonates it: it would delete 36 of the 618 direct
	// endpoints across 21 corpus trees, among them wp-file-upload's
	// wfu_file_downloader.php, whose line 161 reads
	// `require_once $wfu_downloader_data['wfu_ABSPATH'].'wp-load.php';` and
	// which is the only unauthenticated endpoint reaching the ground truth of
	// CVE-2024-11613. Only the defined() branch may reject.
	directBootstrapGuardPattern = regexp.MustCompile(
		`defined\s*\(\s*['"](?:ABSPATH|WPINC)['"]\s*\)`)
)

// directMaxFileBytes bounds how much of one PHP file the direct-access scan
// reads. The scan needs whole-file content (see analyzeDirectPHPFile), and this
// package walks entire plugin trees, so a source file larger than this -- which
// in practice is generated or minified data, not hand-written request handling
// -- is read only up to the bound rather than pulled into memory whole.
const directMaxFileBytes = 4 << 20

// directSkipSet builds the directory-exclusion set for the direct-access walk
// from the analyzer's own vendor configuration.
//
// This file used to keep a second, hand-written list -- vendor, node_modules,
// templates, views and partials -- which disagreed with the list every other
// pass walks with (Analyzer.findPHPFiles, via config.VendorDirConfig). Two
// policies mean the direct pass can emit an endpoint in a file nothing else ever
// parsed, and can miss one in a file everything else did. The
// templates/views/partials half was wrong on its own terms as well: WordPress
// ships no server rule that treats those directory names specially, so
// wp-content/plugins/<slug>/templates/anything.php is fetchable by anyone on a
// stock Apache or nginx install exactly like any other path. Dropping those
// three names brings 199 files in 40 corpus plugins back into consideration.
func directSkipSet(cfg *config.VendorDirConfig) map[string]struct{} {
	if cfg == nil {
		cfg = config.DefaultVendorDirConfig()
	}
	set := make(map[string]struct{}, len(cfg.SkipPatterns))
	for _, p := range cfg.SkipPatterns {
		set[strings.ToLower(p)] = struct{}{}
	}
	return set
}

// DetectDirectPHPEndpoints finds the PHP files in a plugin that a web server
// will execute when they are requested by URL.
func DetectDirectPHPEndpoints(pluginDir, pluginSlug string) []models.Endpoint {
	return DetectDirectPHPEndpointsWithConfig(pluginDir, pluginSlug, nil)
}

// DetectDirectPHPEndpointsWithConfig is DetectDirectPHPEndpoints with an
// explicit vendor-exclusion policy, so a caller holding a customised
// config.Config can hand the direct pass the same file set the rest of the
// analyzer walks. A nil config means the package default.
func DetectDirectPHPEndpointsWithConfig(pluginDir, pluginSlug string, vendorCfg *config.VendorDirConfig) []models.Endpoint {
	var endpoints []models.Endpoint

	if vendorCfg == nil {
		vendorCfg = config.DefaultVendorDirConfig()
	}
	skipSet := directSkipSet(vendorCfg)
	absRoot, _ := filepath.Abs(pluginDir)

	filepath.WalkDir(pluginDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if _, skip := skipSet[strings.ToLower(d.Name())]; skip {
				return filepath.SkipDir
			}
			// The same embedded-package heuristic Analyzer.findPHPFiles applies,
			// so that the two walks cover the same files.
			if vendorCfg.SkipComposerDirs {
				absPath, _ := filepath.Abs(path)
				if absPath != absRoot {
					if _, statErr := os.Stat(filepath.Join(path, "composer.json")); statErr == nil {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}

		ep := analyzeDirectPHPFile(path, pluginDir, pluginSlug)
		if ep != nil {
			endpoints = append(endpoints, *ep)
		}
		return nil
	})

	return endpoints
}

// readDirectFile reads a PHP file for the direct-access scan, bounded by
// directMaxFileBytes.
func readDirectFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return "", false
	}
	size := st.Size()
	if size <= 0 {
		return "", false
	}
	if size > directMaxFileBytes {
		size = directMaxFileBytes
	}

	// The package's shared read buffer, as Analyzer.readFileContent uses it: the
	// direct pass touches every PHP file in the tree, and an allocation per file
	// is exactly the pattern the pool exists to avoid.
	bufPtr := fileBufferPool.Get().(*[]byte)
	buf := *bufPtr
	if int64(cap(buf)) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}

	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
		return "", false
	}
	if n <= 0 {
		*bufPtr = buf
		fileBufferPool.Put(bufPtr)
		return "", false
	}

	content := string(buf[:n])
	*bufPtr = buf
	fileBufferPool.Put(bufPtr)
	return content, true
}

func analyzeDirectPHPFile(path, pluginDir, pluginSlug string) *models.Endpoint {
	// The whole file is read, not its first hundred lines.
	//
	// The window was the single largest source of missed direct endpoints: 724
	// files in 94 of the 143 corpus plugins have their only ungated superglobal
	// read past line 100, and a request to such a file executes it in full, so
	// where the read sits in the file has nothing to do with whether the file is
	// an entry point. The window also made the bootstrap guard unreliable, since
	// a guard past line 100 was invisible.
	content, ok := readDirectFile(path)
	if !ok || content == "" {
		return nil
	}

	if !directSuperglobalPattern.MatchString(content) && !directPhpInputPattern.MatchString(content) {
		return nil
	}

	// A bootstrap guard only counts when it is what the file does first.
	//
	// Matching the guard anywhere in the file would reject any file that checks
	// defined('ABSPATH') halfway down, after it has already acted on request
	// data; the guard has to run before anything else for the file to be
	// unreachable. scanPHPTopLevel finds the first statement that executes at
	// brace depth zero -- skipping namespace, use, declare and the declarations
	// that execute nothing -- and the guard must live inside it.
	//
	// A file whose top level executes nothing has no guard by this rule and is
	// still emitted; see the note on declaration-only files below.
	if top := scanPHPTopLevel(content); top.firstStmt >= 0 {
		if directBootstrapGuardPattern.MatchString(content[top.firstStmt:top.firstStmtEnd]) {
			return nil
		}
	}

	// There is deliberately no rejection here for a file that declares a class
	// or a function and executes nothing at top level, although such a file
	// genuinely runs nothing when it is requested. It is not a rare shape: 392
	// of the 618 endpoints this pass used to emit across the corpus were of it,
	// and 1,242 of the 2,334 it emits now, in 92 of 143 plugins.
	//
	// The reason is the priority order this library is tuned to. A spurious
	// direct endpoint is reported Unauthenticated, so it can only ever pull a
	// reported privilege DOWN, which is noise. Deleting endpoints is the one
	// move that can push a reported privilege UP, and an over-restriction hides
	// a real bug. A conservative depth-zero test measured over the corpus drops
	// roughly half of the direct endpoints across 54 trees and touches the
	// evidence of 38 entries that currently answer correctly, and the score
	// records expose too few of those matches to prove that none of them depends
	// on such an endpoint. The scan that would make the rejection safe now
	// exists (scanPHPTopLevel); landing the rejection itself belongs in its own
	// separately measured change.
	//
	// The rule that stood here before was inert in any case: it re-tested the
	// superglobal condition already established a few lines above, so it could
	// never reject anything, and it was reached through a first-code-line test
	// that also rejected every file declaring a namespace. `namespace` is a
	// compile-time name-resolution directive and does not suppress top-level
	// execution, so that one line discarded 602 files in 68 corpus plugins --
	// among them the unauthenticated RCE of CVE-2023-6553 (backup-backup 1.3.7,
	// includes/backup-heart.php, which opens `namespace BMI\Plugin\Heart;` and
	// then acts on $_SERVER and $_POST with no guard anywhere in the file).

	relPath, err := filepath.Rel(pluginDir, path)
	if err != nil {
		relPath = path
	}

	return &models.Endpoint{
		PluginSlug: pluginSlug,
		Type:       models.EndpointTypeDirect,
		Route:      relPath,
		Method:     "GET/POST",
		AuthLevel:  models.Unauthenticated,
		// The unit that executes is the file's own top-level statement list, not
		// any function in it, so the callback names the file scope rather than a
		// symbol. It is written with forward slashes because the resolvers that
		// consume a callback split fully-qualified names on backslash, and an
		// endpoint's File is backslash-separated on Windows.
		//
		// Naming the file scope is only half the repair: the call graph has to
		// carry a matching `file:<relpath>` node whose edges are the calls, the
		// `new` expressions and the resolvable includes of those depth-zero
		// statements, or a walk rooted here still ends where it starts. Until
		// that lands this key behaves exactly as the bare filename it replaces
		// -- the endpoint contributes its own file and that file's include
		// closure, and nothing more.
		Callback: "file:" + filepath.ToSlash(relPath),
		File:     relPath,
		// A requested file starts executing at its first line. The field was
		// left at zero before, which is not a position any file has.
		Line: 1,
	}
}

// DetectDirectPHPEndpointsWithAST wraps DetectDirectPHPEndpoints for callers
// that hold an AST context.
//
// It deliberately does NOT reclassify a direct endpoint's auth level from the
// AST. It used to: it looked up "file:"+ep.File and, when
// Resolver.HasAuthGuardBeforeInput reported a guard, wrote that level onto the
// endpoint. The lookup has never resolved -- the symbol table registers function
// and method declarations only, so no `file:` symbol exists -- which is the sole
// reason the write has been harmless so far.
//
// It must not be armed. The level a direct endpoint carries is a statement about
// the REQUEST: wp-content/plugins/** is served verbatim by a stock WordPress
// install, so anyone can issue it, and that is Unauthenticated by construction.
// The AST helper answers a different question. It walks the whole body and
// returns the HIGHEST capability mentioned anywhere inside it, with no
// requirement that the check dominate the use of request data, so a file that
// gates one branch on current_user_can('manage_options') and handles the
// attacker's branch ungated would be reported Admin. 527 of the 1,895
// direct-access candidates in the corpus, in 81 of 143 plugins, name such a
// check somewhere in the file. Reporting a higher privilege than the truth is
// the one error that makes a reachable vulnerability look gated, so the whole
// class is refused here rather than gambled on the guard being dominant.
func DetectDirectPHPEndpointsWithAST(pluginDir, pluginSlug string, astCtx *wpast.ASTContext) []models.Endpoint {
	_ = astCtx
	return DetectDirectPHPEndpoints(pluginDir, pluginSlug)
}

// phpTopLevel describes what a PHP file does when a web server executes it.
//
// firstStmt is the byte offset of the first statement that runs at brace depth
// zero, and firstStmtEnd is one past its last byte. Both are -1 when the file
// declares things and executes nothing -- a class-only or function-only library
// file, which produces no output and takes no action when it is requested.
type phpTopLevel struct {
	firstStmt    int
	firstStmtEnd int
}

// phpTopLevelDeclarators are the keywords that open a top-level construct which
// declares rather than executes. A file may open with any number of them before
// its first real statement, and a bootstrap guard is still the first thing that
// runs.
//
// `function` is here because a top-level `function f() {}` is a declaration;
// PHP's other use of the word, an anonymous function, cannot open a statement on
// its own. `const` declares a compile-time constant, unlike define(), which is a
// call and therefore executes.
var phpTopLevelDeclarators = map[string]bool{
	"namespace": true, "use": true, "declare": true,
	"class": true, "interface": true, "trait": true, "enum": true,
	"abstract": true, "final": true, "readonly": true,
	"function": true, "const": true,
}

// scanPHPTopLevel walks a PHP source file the way the interpreter enters it and
// reports where its first executing top-level statement begins and ends.
//
// It has to be PHP-mode aware rather than a plain brace counter. A file that
// closes the tag and emits markup -- `?> <style>.x{color:red}</style> <?php` --
// has braces in the HTML that belong to no PHP block, and counting them
// desynchronises the depth so that every later statement looks nested. 163 of
// the corpus's direct-access candidates, in 54 plugins, close and reopen PHP
// mode with a brace in the emitted region, and 26 of those also contain a
// heredoc. Strings, heredocs, nowdocs and comments are skipped for the same
// reason.
//
// Where it is imprecise it is imprecise in the direction that emits an endpoint:
// failing to find the first statement, or finding a later one, can only mean a
// bootstrap guard goes unnoticed and the file is reported as reachable. A braced
// namespace block (`namespace X { ... }`) is one such case -- its body is really
// top-level code, and this reads the whole block as a single declaration.
func scanPHPTopLevel(content string) phpTopLevel {
	res := phpTopLevel{firstStmt: -1, firstStmtEnd: -1}

	n := len(content)
	i := 0
	inPHP := false
	depth := 0
	stmtStart := -1
	stmtIsDecl := false

	// finish closes the statement that is open at depth zero, recording it as
	// the first executing one when it executes anything.
	finish := func(end int) {
		if stmtStart >= 0 && !stmtIsDecl && res.firstStmt < 0 {
			res.firstStmt = stmtStart
			res.firstStmtEnd = end
		}
		stmtStart = -1
		stmtIsDecl = false
	}

	for i < n {
		if !inPHP {
			// Everything outside the tags is output, and output is execution.
			// Only whitespace between a `?>` and the next `<?php` runs nothing.
			open := strings.Index(content[i:], "<?")
			end := n
			if open >= 0 {
				end = i + open
			}
			if strings.TrimSpace(content[i:end]) != "" && res.firstStmt < 0 {
				res.firstStmt = i
				res.firstStmtEnd = end
			}
			if open < 0 {
				break
			}
			i = end + 2
			tagEnd := i + 3
			if tagEnd > n {
				tagEnd = n
			}
			if strings.EqualFold(content[i:tagEnd], "php") {
				i += 3
			} else if i < n && content[i] == '=' {
				// `<?=` is shorthand for echo, so it opens a statement.
				i++
			}
			inPHP = true
			continue
		}

		c := content[i]

		switch {
		case c == '?' && i+1 < n && content[i+1] == '>':
			// A close tag terminates the statement in progress.
			finish(i)
			inPHP = false
			i += 2
			continue

		case c == '/' && i+1 < n && content[i+1] == '/':
			i = skipPHPLineComment(content, i+2)
			continue

		case c == '#' && !(i+1 < n && content[i+1] == '['):
			i = skipPHPLineComment(content, i+1)
			continue

		case c == '/' && i+1 < n && content[i+1] == '*':
			if end := strings.Index(content[i+2:], "*/"); end >= 0 {
				i = i + 2 + end + 2
			} else {
				i = n
			}
			continue

		case c == '\'' || c == '"' || c == '`':
			if depth == 0 && stmtStart < 0 {
				stmtStart = i
				stmtIsDecl = false
			}
			i = skipPHPQuoted(content, i)
			continue

		case c == '<' && strings.HasPrefix(content[i:], "<<<"):
			if depth == 0 && stmtStart < 0 {
				stmtStart = i
				stmtIsDecl = false
			}
			i = skipPHPHeredoc(content, i)
			continue

		case c == '{':
			depth++
			i++
			continue

		case c == '}':
			if depth > 0 {
				depth--
			}
			if depth == 0 {
				// A block that closes at depth zero ends the statement it
				// belongs to: `if (...) { ... }`, `class X { ... }`.
				finish(i + 1)
			}
			i++
			continue

		case c == ';':
			if depth == 0 {
				finish(i + 1)
			}
			i++
			continue

		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
			continue

		default:
			if depth == 0 && stmtStart < 0 {
				stmtStart = i
				// A PHP 8 attribute annotates a declaration and never opens an
				// executing statement, so `#[Attr]` marks what follows as one.
				if c == '#' {
					stmtIsDecl = true
					i++
					continue
				}
				word, next := phpLeadingWord(content, i)
				stmtIsDecl = phpTopLevelDeclarators[word]
				if word != "" {
					i = next
					continue
				}
			}
			i++
		}
	}

	// A file that ends while a statement is still open still executed it.
	finish(n)

	return res
}

// skipPHPLineComment returns the offset just past a // or # comment. PHP ends
// such a comment at a close tag as well as at a newline, so `// x ?>` leaves PHP
// mode.
func skipPHPLineComment(content string, i int) int {
	for i < len(content) {
		if content[i] == '\n' {
			return i + 1
		}
		if content[i] == '?' && i+1 < len(content) && content[i+1] == '>' {
			return i
		}
		i++
	}
	return len(content)
}

// skipPHPQuoted returns the offset just past the quoted string starting at i.
func skipPHPQuoted(content string, i int) int {
	quote := content[i]
	i++
	for i < len(content) {
		if content[i] == '\\' {
			i += 2
			continue
		}
		if content[i] == quote {
			return i + 1
		}
		i++
	}
	return len(content)
}

// skipPHPHeredoc returns the offset just past the heredoc or nowdoc starting at
// i, which is the `<<<` itself. The body ends at the first line whose first
// non-whitespace token is the label and which is not followed by a further
// identifier character; PHP 7.3 and later allow that closing label to be
// indented.
func skipPHPHeredoc(content string, i int) int {
	n := len(content)
	j := i + 3
	for j < n && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	if j < n && (content[j] == '\'' || content[j] == '"') {
		q := content[j]
		j++
		start := j
		for j < n && content[j] != q {
			j++
		}
		return heredocBodyEnd(content, content[start:j], j+1)
	}
	start := j
	for j < n && isPHPWordByte(content[j]) {
		j++
	}
	if j == start {
		// Not a heredoc after all (a `<<<` appearing in some other position);
		// step past the operator so the scan makes progress.
		return i + 3
	}
	return heredocBodyEnd(content, content[start:j], j)
}

func heredocBodyEnd(content, label string, i int) int {
	n := len(content)
	if label == "" {
		return i
	}
	for i < n {
		nl := strings.IndexByte(content[i:], '\n')
		if nl < 0 {
			return n
		}
		i += nl + 1
		k := i
		for k < n && (content[k] == ' ' || content[k] == '\t') {
			k++
		}
		if strings.HasPrefix(content[k:], label) {
			after := k + len(label)
			if after >= n || !isPHPWordByte(content[after]) {
				return after
			}
		}
	}
	return n
}

// phpLeadingWord reads the identifier at i, returning it lowercased along with
// the offset just past it. A leading backslash is consumed so that `\Foo::bar()`
// reads as an ordinary statement rather than an unknown token.
func phpLeadingWord(content string, i int) (string, int) {
	n := len(content)
	j := i
	if j < n && content[j] == '\\' {
		j++
	}
	start := j
	for j < n && isPHPWordByte(content[j]) {
		j++
	}
	if j == start {
		return "", i
	}
	return strings.ToLower(content[start:j]), j
}

func isPHPWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
