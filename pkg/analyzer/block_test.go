package analyzer

import (
	"strings"
	"testing"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

// Since WordPress 5.8 the first argument to register_block_type may be a block
// name, a path to a block.json or a path to the directory holding one, and
// register_block_type_from_metadata is the other spelling of the same call. What
// makes a block reachable is the render_callback in the second argument, not how
// the first argument is spelled, so all four shapes must produce the callback.
func TestBlockRegistrationShapes(t *testing.T) {
	cases := map[string]string{
		"literal name":  `<?php register_block_type( 'ns/x', array( 'render_callback' => 'rc' ) );`,
		"dir path":      `<?php register_block_type( __DIR__ . '/build/blk', array( 'render_callback' => 'rc' ) );`,
		"variable":      `<?php register_block_type( $name, array( 'render_callback' => 'rc' ) );`,
		"from metadata": `<?php register_block_type_from_metadata( __DIR__, array( 'render_callback' => 'rc' ) );`,
		"multiline":     "<?php\nregister_block_type(\n\t__DIR__ . '/build/blk',\n\tarray(\n\t\t'render_callback' => 'rc',\n\t)\n);",
		"short array":   `<?php register_block_type( 'ns/y', [ 'render_callback' => 'rc' ] );`,
	}

	for name, php := range cases {
		t.Run(name, func(t *testing.T) {
			eps := DetectBlocks(php, "b.php", "p")
			if len(eps) != 2 {
				t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
			}
			for _, ep := range eps {
				if ep.Callback != "rc" {
					t.Errorf("endpoint %q has callback %q, want rc", ep.Route, ep.Callback)
				}
				if ep.Line <= 0 {
					t.Errorf("endpoint %q has no line", ep.Route)
				}
			}
		})
	}
}

// A dynamic block is reachable two ways, at two levels, through one callback:
// do_blocks() renders it from the_content for any visitor, and
// /wp-json/wp/v2/block-renderer/<name> runs it with request-supplied attributes
// behind current_user_can('edit_posts'). Because a function's reported level is
// the minimum over the endpoints reaching it, the Contributor endpoint cannot
// raise anything above the Unauthenticated one beside it.
func TestBlockDynamicBlockHasBothRequestPaths(t *testing.T) {
	php := `<?php register_block_type( 'ns/card', array( 'render_callback' => array( $this, 'render_card' ) ) );`
	eps := DetectBlocks(php, "b.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}
	render := epByRoute(t, eps, "block:ns/card:render")
	if render.AuthLevel != models.Unauthenticated || render.Callback != "render_card" {
		t.Errorf("render = %v / %q", render.AuthLevel, render.Callback)
	}
	renderer := epByRoute(t, eps, "block:ns/card:block-renderer")
	if renderer.AuthLevel != models.Contributor || renderer.Callback != "render_card" {
		t.Errorf("block-renderer = %v / %q", renderer.AuthLevel, renderer.Callback)
	}
	assertUsableCallbacks(t, eps)
	for _, ep := range eps {
		if ep.Callback == "(Gutenberg editor)" {
			t.Errorf("a dynamic block still carries the sentinel callback")
		}
	}
}

// The bound in the other direction. A block with no render_callback is not
// dynamic, so /wp/v2/block-renderer refuses it and there is no PHP for a
// Contributor endpoint to point at. The editor endpoint stays exactly as it was
// -- same level, same unresolvable callback -- because it is honest file-level
// evidence that the editor screen loads this file, and deleting an endpoint is
// the one move that can raise a reported privilege.
func TestBlockStaticBlockKeepsItsEditorEndpointUnchanged(t *testing.T) {
	php := `<?php register_block_type( 'ns/static', array( 'editor_script' => 'ns-static' ) );`
	eps := DetectBlocks(php, "b.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
	ep := eps[0]
	if ep.Route != "block:ns/static:editor" {
		t.Errorf("route = %q", ep.Route)
	}
	if ep.AuthLevel != models.Contributor {
		t.Errorf("auth level = %v, want contributor", ep.AuthLevel)
	}
	if ep.Callback != "(Gutenberg editor)" {
		t.Errorf("callback = %q; a static block must NOT be given a resolvable "+
			"callback, or its Contributor level starts gating functions nothing "+
			"else reaches", ep.Callback)
	}
}

// A route that is not unique per registration site turns a discovery fix into a
// discovery loss: deduplicateEndpoints keys on Route|Method|Type across the whole
// plugin, so a loop registering several blocks from one unresolvable expression
// would have all but one of its render callbacks found and then discarded.
func TestBlockDynamicRoutesAreUniquePerSite(t *testing.T) {
	php := `<?php
foreach ( array( 'alpha', 'beta', 'gamma' ) as $b ) {
	register_block_type( __DIR__ . '/build/' . $b, array( 'render_callback' => 'render_alpha' ) );
}
register_block_type( __DIR__ . '/build/' . $b, array( 'render_callback' => 'render_beta' ) );
`
	eps := DetectBlocks(php, "inc/blocks.php", "p")
	seen := map[string]bool{}
	for _, ep := range eps {
		if seen[ep.Route] {
			t.Fatalf("duplicate route %q", ep.Route)
		}
		seen[ep.Route] = true
	}
	if len(eps) != 4 {
		t.Fatalf("want 4 endpoints from 2 sites, got %d: %v", len(eps), slashRoutes(eps))
	}
	// The discriminator has to name the file and the line, since two sites in
	// different files can carry the identical expression.
	for _, ep := range eps {
		if !strings.Contains(ep.Route, "inc/blocks.php") {
			t.Errorf("route %q does not identify its registration site", ep.Route)
		}
	}
}

func TestBlockRenderCallbackShapes(t *testing.T) {
	cases := map[string]struct {
		php  string
		want string
	}{
		"string":        {`<?php register_block_type( 'a/b', array( 'render_callback' => 'rc' ) );`, "rc"},
		"this bracket":  {`<?php register_block_type( 'a/b', [ 'render_callback' => [ $this, 'rc' ] ] );`, "rc"},
		"this array":    {`<?php register_block_type( 'a/b', array( 'render_callback' => array( $this, 'rc' ) ) );`, "rc"},
		"class const":   {`<?php register_block_type( 'a/b', array( 'render_callback' => array( __CLASS__, 'rc' ) ) );`, "rc"},
		"class name":    {`<?php register_block_type( 'a/b', [ 'render_callback' => [ Acme::class, 'rc' ] ] );`, "Acme::rc"},
		"class array":   {`<?php register_block_type( 'a/b', array( 'render_callback' => array( Acme::class, 'rc' ) ) );`, "Acme::rc"},
		"self":          {`<?php register_block_type( 'a/b', [ 'render_callback' => [ self::class, 'rc' ] ] );`, "self::rc"},
		"static":        {`<?php register_block_type( 'a/b', [ 'render_callback' => [ static::class, 'rc' ] ] );`, "static::rc"},
		"object var":    {`<?php register_block_type( 'a/b', [ 'render_callback' => [ $renderer, 'rc' ] ] );`, "rc"},
		"static string": {`<?php register_block_type( 'a/b', array( 'render_callback' => 'Acme::rc' ) );`, "Acme::rc"},
		"closure":       {`<?php register_block_type( 'a/b', array( 'render_callback' => function ( $a, $c ) { return ''; } ) );`, "anonymous"},
		"arrow":         {`<?php register_block_type( 'a/b', array( 'render_callback' => fn ( $a ) => '' ) );`, "anonymous"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			eps := DetectBlocks(tc.php, "b.php", "p")
			if len(eps) != 2 {
				t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
			}
			if eps[0].Callback != tc.want {
				t.Errorf("callback = %q, want %q", eps[0].Callback, tc.want)
			}
		})
	}
}

// A registration with a single argument names a block but no callback, so it is
// a static block. It used to be invisible: the old pattern required a comma
// after the literal name and then searched for the next comma anywhere in the
// file.
func TestBlockSingleArgumentRegistration(t *testing.T) {
	php := `<?php register_block_type( 'ns/only' );`
	eps := DetectBlocks(php, "b.php", "p")
	if len(eps) != 1 || eps[0].Route != "block:ns/only:editor" {
		t.Fatalf("want one editor endpoint, got %v", slashRoutes(eps))
	}
}

// When one name is registered twice in a file, the registration that names a
// render callback is the informative one.
func TestBlockPrefersTheRegistrationWithACallback(t *testing.T) {
	php := `<?php
register_block_type( 'ns/dup', array( 'editor_script' => 's' ) );
register_block_type( 'ns/dup', array( 'render_callback' => 'rc' ) );
`
	eps := DetectBlocks(php, "b.php", "p")
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %v", len(eps), slashRoutes(eps))
	}
	if !hasCallback(eps, "rc") {
		t.Errorf("the render callback was dropped; got %v", callbacksOf(eps))
	}
}

// A plugin that registers its blocks in a loop over a directory listing has one
// unresolvable expression per block and no callback in any of them. Those sites
// all assert the same thing -- this file registers blocks the editor loads -- so
// they collapse to one endpoint rather than one per line. The bound is the test
// above: as soon as a site names a callback, it gets its own route again.
func TestBlockCallbacklessDynamicSitesCollapsePerFile(t *testing.T) {
	php := `<?php
register_block_type( __DIR__ . '/blocks/accordion' );
register_block_type( __DIR__ . '/blocks/column' );
register_block_type( __DIR__ . '/blocks/counter' );
`
	eps := DetectBlocks(php, "init.php", "p")
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d: %v", len(eps), slashRoutes(eps))
	}
	if eps[0].Route != "block:{dynamic}@init.php:editor" {
		t.Errorf("route = %q", eps[0].Route)
	}
	if eps[0].AuthLevel != models.Contributor || eps[0].Callback != "(Gutenberg editor)" {
		t.Errorf("endpoint = %v / %q", eps[0].AuthLevel, eps[0].Callback)
	}
}
