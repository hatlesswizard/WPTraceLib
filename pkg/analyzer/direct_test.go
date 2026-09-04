package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// writeTree lays out a plugin directory from a path -> content map and returns
// its root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func slashRoutes(eps []models.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, filepath.ToSlash(ep.Route))
	}
	return out
}

func hasRoute(eps []models.Endpoint, route string) bool {
	for _, r := range slashRoutes(eps) {
		if r == route {
			return true
		}
	}
	return false
}

// A namespaced file with top-level code that reads request data is exactly as
// requestable as any other file: `namespace` is a compile-time name-resolution
// directive and does not suppress top-level execution. This is the shape of
// backup-backup 1.3.7 includes/backup-heart.php, the corpus's unauthenticated
// RCE (CVE-2023-6553), which the namespace rule discarded.
func TestDirectNamespacedFileIsAnEndpoint(t *testing.T) {
	root := writeTree(t, map[string]string{
		"includes/backup-heart.php": `<?php
// Namespace
namespace BMI\Plugin\Heart;

// Allow only POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { exit; }

$fields = json_decode(file_get_contents('php://input'), true);
define('ABSPATH', $fields['content-abs']);
require_once BMI_INCLUDES . '/bypasser.php';
`,
	})

	eps := DetectDirectPHPEndpoints(root, "backup-backup")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
	ep := eps[0]
	if got := filepath.ToSlash(ep.Route); got != "includes/backup-heart.php" {
		t.Errorf("route = %q", got)
	}
	if ep.AuthLevel != models.Unauthenticated {
		t.Errorf("auth level = %v, want unauthenticated", ep.AuthLevel)
	}
	if ep.Callback != "file:includes/backup-heart.php" {
		t.Errorf("callback = %q, want the file-scope key", ep.Callback)
	}
	if ep.Line != 1 {
		t.Errorf("line = %d, want 1", ep.Line)
	}
}

// The bound on the namespace change: a real bootstrap guard, as the first thing
// the file does, still rejects it. Both spellings are in wide use.
func TestDirectBootstrapGuardStillRejects(t *testing.T) {
	for name, body := range map[string]string{
		"if-not-defined": `<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
$x = $_GET['x'];
echo $x;
`,
		"or-exit": `<?php
defined( 'ABSPATH' ) || exit;
$x = $_POST['x'];
`,
		"wpinc": `<?php
if ( ! defined( 'WPINC' ) ) { die; }
$x = $_REQUEST['x'];
`,
		"after-namespace-and-use": `<?php
namespace Acme\Thing;

use Acme\Other\Helper;

defined( 'ABSPATH' ) or exit;

$x = $_GET['x'];
`,
	} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"a.php": body})
			if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 0 {
				t.Fatalf("want no endpoint, got %v", slashRoutes(eps))
			}
		})
	}
}

// A guard only counts when it is what the file does first. A file that has
// already acted on request data before it checks defined('ABSPATH') is
// requestable, and the check does not undo what ran above it.
func TestDirectNonDominatingGuardDoesNotReject(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.php": `<?php
$action = $_GET['action'];
do_something( $action );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
`,
	})
	if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
}

// Loading wp-load.php is the file bootstrapping WordPress FOR ITSELF, which is
// the reason it is directly requestable -- the opposite of a guard. This is the
// shape of wp-file-upload's wfu_file_downloader.php, whose endpoint is the only
// unauthenticated one reaching the ground truth of CVE-2024-11613.
func TestDirectSelfBootstrapIsNotAGuard(t *testing.T) {
	root := writeTree(t, map[string]string{
		"wfu_file_downloader.php": `<?php
$data = json_decode( base64_decode( $_GET['file'] ), true );
require_once $data['ABSPATH'] . 'wp-load.php';
readfile( $data['path'] );
`,
	})
	if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
}

// The window: a file whose only request-data read sits past line 100 is still an
// entry point, because a request executes the file in full.
func TestDirectInputPastTheOldHundredLineWindow(t *testing.T) {
	body := "<?php\n" + strings.Repeat("$noop = 1;\n", 200) + "echo $_GET['q'];\n"
	root := writeTree(t, map[string]string{"a.php": body})
	if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
}

// WordPress ships no server rule that treats templates/, views/ or partials/
// specially, so those files are fetchable like any other path. vendor/ and the
// rest of the analyzer's own exclusion policy still apply, and they are the
// bound: the direct walk must cover exactly the file set the other passes read.
func TestDirectDirectoryExclusionsFollowTheAnalyzerPolicy(t *testing.T) {
	root := writeTree(t, map[string]string{
		"templates/form.php":     `<?php echo $_GET['a'];`,
		"views/list.php":         `<?php echo $_GET['b'];`,
		"partials/row.php":       `<?php echo $_GET['c'];`,
		"vendor/lib/x.php":       `<?php echo $_GET['d'];`,
		"node_modules/pkg/y.php": `<?php echo $_GET['e'];`,
		"embedded/composer.json": `{"name":"acme/embedded"}`,
		"embedded/src/z.php":     `<?php echo $_GET['f'];`,
	})

	eps := DetectDirectPHPEndpoints(root, "p")
	for _, want := range []string{"templates/form.php", "views/list.php", "partials/row.php"} {
		if !hasRoute(eps, want) {
			t.Errorf("missing endpoint for %s; got %v", want, slashRoutes(eps))
		}
	}
	for _, notWant := range []string{"vendor/lib/x.php", "node_modules/pkg/y.php", "embedded/src/z.php"} {
		if hasRoute(eps, notWant) {
			t.Errorf("unexpected endpoint for %s", notWant)
		}
	}
}

// A file that declares a class and executes nothing at top level runs nothing
// when it is requested, so in principle it is not an endpoint. It is still
// emitted, deliberately: the endpoint is Unauthenticated, so it can only pull a
// reported privilege down, whereas deleting endpoints is the one move that can
// push one up and hide a reachable bug. This test pins that decision so a later
// change to it is a deliberate one, measured on its own.
func TestDirectDeclarationOnlyFileIsStillEmitted(t *testing.T) {
	root := writeTree(t, map[string]string{
		"class-thing.php": `<?php
namespace Acme;

class Thing {
	public function run() {
		echo $_GET['a'];
	}
}
`,
	})
	if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
}

// The AST reclassification is not armed. HasAuthGuardBeforeInput returns the
// highest capability named anywhere in a body, with no requirement that the
// check dominate the use of request data, and a direct endpoint's level is a
// statement about the request rather than about the body. Raising it would
// report a higher privilege than the truth, which is the error that hides a
// reachable bug.
func TestDirectWithASTDoesNotRaiseTheLevel(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a.php": `<?php
$action = $_GET['action'];
if ( $action === 'admin_export' ) {
	if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }
	do_export();
}
handle_public_ping( $action );
`,
	})

	plain := DetectDirectPHPEndpoints(root, "p")
	withAST := DetectDirectPHPEndpointsWithAST(root, "p", nil)
	if len(plain) != 1 || len(withAST) != 1 {
		t.Fatalf("want 1 endpoint each, got %d and %d", len(plain), len(withAST))
	}
	if withAST[0].AuthLevel != models.Unauthenticated {
		t.Errorf("auth level = %v, want unauthenticated", withAST[0].AuthLevel)
	}
	if plain[0].Route != withAST[0].Route || plain[0].Callback != withAST[0].Callback ||
		plain[0].AuthLevel != withAST[0].AuthLevel || plain[0].Line != withAST[0].Line {
		t.Errorf("AST wrapper changed the endpoint:\n plain   = %+v\n withAST = %+v", plain[0], withAST[0])
	}
}

func TestScanPHPTopLevel(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		want    string // the text of the first executing top-level statement
		wantNil bool
	}{
		{
			name: "guard is the first statement",
			src:  "<?php\nif ( ! defined( 'ABSPATH' ) ) { exit; }\n$x = $_GET['a'];\n",
			want: "if ( ! defined( 'ABSPATH' ) ) { exit; }",
		},
		{
			name: "declarations do not count",
			src:  "<?php\nnamespace A\\B;\nuse C\\D;\ndeclare(strict_types=1);\ndefined('ABSPATH') || exit;\n",
			want: "defined('ABSPATH') || exit;",
		},
		{
			name: "a class declaration is not a statement",
			src:  "<?php\nnamespace A;\nclass T { function f() { echo $_GET['a']; } }\n",
			// A file that only declares runs nothing at all.
			wantNil: true,
		},
		{
			// Braces inside emitted markup belong to no PHP block. Counting them
			// desynchronises the depth and every later statement looks nested;
			// 163 of the corpus's direct-access candidates, in 54 plugins, have
			// this shape.
			name: "braces in html between php regions",
			src:  "<?php function helper(){ return 1; } ?>\n<style>.x{color:red}</style>\n<?php echo $_GET['q']; ?>\n",
			want: "\n<style>.x{color:red}</style>\n",
		},
		{
			name: "heredoc body is not code",
			src: "<?php\n$sql = <<<SQL\n  if ( ! defined( 'ABSPATH' ) ) { exit; }\nSQL;\n" +
				"echo $_GET['a'];\n",
			want: "$sql = <<<SQL\n  if ( ! defined( 'ABSPATH' ) ) { exit; }\nSQL;",
		},
		{
			name: "nowdoc body is not code",
			src: "<?php\n$t = <<<'TXT'\n{ defined('ABSPATH') }\nTXT;\n" +
				"echo $_POST['a'];\n",
			want: "$t = <<<'TXT'\n{ defined('ABSPATH') }\nTXT;",
		},
		{
			name: "a guard inside a string is not a guard",
			src:  "<?php\n$msg = \"defined( 'ABSPATH' )\";\necho $_GET['a'];\n",
			want: "$msg = \"defined( 'ABSPATH' )\";",
		},
		{
			name: "comments are skipped",
			src:  "<?php\n// defined( 'ABSPATH' ) || exit;\n/* defined('WPINC') */\n# defined('ABSPATH')\n$x = 1;\n",
			want: "$x = 1;",
		},
		{
			name: "attributes precede a declaration",
			src:  "<?php\n#[Attr]\nfunction f() {}\n",
			// #[Attr] opens a declaration, and the function is one too.
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanPHPTopLevel(tc.src)
			if tc.wantNil {
				if got.firstStmt >= 0 {
					t.Fatalf("want no executing statement, got %q",
						tc.src[got.firstStmt:got.firstStmtEnd])
				}
				return
			}
			if got.firstStmt < 0 {
				t.Fatalf("want %q, got no statement", tc.want)
			}
			if stmt := tc.src[got.firstStmt:got.firstStmtEnd]; stmt != tc.want {
				t.Fatalf("first statement =\n%q\nwant\n%q", stmt, tc.want)
			}
		})
	}
}

// The markup case end to end: the guard sits after the emitted HTML, so the
// depth scan must not lose the file.
func TestDirectHtmlInterleavedFileIsAnEndpoint(t *testing.T) {
	root := writeTree(t, map[string]string{
		"tpl.php": "<?php function helper(){ return 1; } ?>\n" +
			"<style>.x{color:red}</style>\n" +
			"<?php echo $_GET['q']; ?>\n",
	})
	if eps := DetectDirectPHPEndpoints(root, "p"); len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
}
