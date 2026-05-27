# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WPTraceLib is a Go-based static analysis tool for WordPress plugin security research. It scans WordPress plugins to detect API endpoints (REST, AJAX, Admin Pages) and categorizes them by the WordPress role hierarchy:

```
SuperAdmin > Admin > Editor > Author > Contributor > Subscriber > Unauthenticated
```

## Build and Run Commands

```bash
# Build the CLI tool
go build ./cmd/wptracelib

# Run without building
go run ./cmd/wptracelib [flags]

# Run tests
go test ./...

# Run a single test
go test -run TestFunctionName ./pkg/config/

# Run tests with coverage
go test -cover ./...

# Run validation against manual analysis results
go run validate.go
```

## CLI Usage

```bash
# Analyze existing plugins in a directory (auto-detects single plugin vs multi-plugin directories)
./wptracelib -analyze ./plugins
./wptracelib -analyze ./plugins/contact-form-7  # works on single plugin directory too

# Download and analyze popular plugins (first 5 pages)
./wptracelib -pages 5 -output ./plugins

# Show only statistics (no endpoint list)
./wptracelib -analyze ./plugins -stats

# Filter by auth level (7 levels)
./wptracelib -analyze ./plugins -unauth       # unauthenticated only
./wptracelib -analyze ./plugins -subscriber   # subscriber-level only
./wptracelib -analyze ./plugins -contributor  # contributor-level only
./wptracelib -analyze ./plugins -author       # author-level only
./wptracelib -analyze ./plugins -editor       # editor-level only
./wptracelib -analyze ./plugins -admin        # admin-level only
./wptracelib -analyze ./plugins -superadmin   # super-admin only
./wptracelib -analyze ./plugins -auth         # all authenticated (subscriber+)
./wptracelib -analyze ./plugins -user         # alias for -subscriber (backwards compat)

# Save output to file
./wptracelib -analyze ./plugins -save report.txt

# List popular plugins without downloading
./wptracelib -list-only

# Call chain analysis (shows function calls from each callback)
./wptracelib -analyze ./plugins -chain-human  # Tree format output
./wptracelib -analyze ./plugins -chain-json   # JSON with nested call chains
```

## Library Usage

WPTraceLib can also be used as a Go library (module: `github.com/hatlesswizard/wptracelib`):

```go
import "github.com/hatlesswizard/wptracelib"

cfg := wptracelib.Config{
    OutputDir: "./plugins",
    Workers:   10,
    ChainMode: analyzer.ChainModeHierarchical, // or ChainModeNone, ChainModeFlat
}
lib := wptracelib.New(cfg)

// Analyze a directory
report, err := lib.AnalyzeDirectory(ctx, "./plugins")

// Or full workflow: fetch, download, analyze
report, err := lib.Run(ctx)
```

## Architecture

### Core Packages

**`pkg/analyzer/`** - Static analysis engine for PHP code
- `analyzer.go` - Main entry point; orchestrates 4-pass analysis pipeline
- `rest.go` - Detects `register_rest_route()` calls with 40+ pattern variants
- `ajax.go` - Detects `add_action('wp_ajax_*')` and 25+ AJAX pattern types
- `admin.go` - Detects admin menu registrations (`add_menu_page`, `add_submenu_page`, etc.)
- `auth.go` - Infers authentication level from capability checks, permission callbacks, and code patterns
- `symbols.go` - PHP symbol table for resolving constants, class properties, and concatenated expressions
- `framework.go` - Detects framework-specific patterns (WooCommerce, ACF, Elementor wrappers)
- `wrappers.go` - Two-pass wrapper detection for plugin-specific hook registration patterns
- `callgraph.go` - Plugin-wide call graph for recursive function call tracking

**`pkg/config/`** - External configuration system
- `config.go` - Main Config struct with capability mappings, detection profiles, and framework settings
- `capabilities.go` - WordPress capability-to-auth-level mappings (core admin/user, extended, custom)
- `plugins.go` - Default detection profiles for common plugins/frameworks
- Supports JSON config files via `LoadFromFile()` for custom detection rules

**`pkg/scraper/`** - WordPress.org plugin catalog scraper
- Fetches popular plugin listings using goquery
- Retrieves plugin metadata from WordPress.org API

**`pkg/downloader/`** - Plugin ZIP downloader and extractor

**`pkg/models/`** - Data structures
- `Endpoint` - Discovered endpoint with route, type, auth level, callback, file location, and `FunctionCalls` (recursive call graph)
- `AuthLevel` - 7-level enum: Unauthenticated, Subscriber, Contributor, Author, Editor, Admin, SuperAdmin
- `EndpointType` - Enum: rest, ajax, admin

**`internal/parser/`** - Low-level PHP parsing utilities

### Key Detection Patterns

The analyzer uses regex patterns to detect WordPress hooks. Key patterns in `rest.go`:
- Standard: `register_rest_route('namespace/v1', '/route', [...])`
- Variable namespace: `register_rest_route($this->namespace, '/route', [...])`
- Wrapper methods: `$this->register_route('/route', [...])`
- Concatenated routes: `'/prefix' . self::CONSTANT . '/suffix'`

Authentication inference (`auth.go`) priority:
1. Explicitly blocked (`__return_false` permission callback) = Excluded from analysis
2. Explicit `__return_true` permission callback = Unauthenticated
3. `current_user_can('capability')` checks mapped to the 7 auth levels via `pkg/config/capabilities.go`
4. Pattern-based capability inference (e.g., `manage_*` → Admin, `edit_others_*` → Editor)
5. Admin capability patterns (`is_super_admin()`, `manage_options`) = Admin/SuperAdmin
6. `is_user_logged_in()` or `auth_redirect()` = Subscriber level
7. Permission callback exists but unanalyzed = Subscriber (conservative)
8. No auth checks found = Unauthenticated

**Important**: `is_admin()` checks location (admin panel), NOT authentication. An unauthenticated user at `/wp-admin/` has `is_admin() === true`. It's intentionally excluded from auth level determination.

### Data Flow

1. **Scrape**: Fetch plugin slugs from WordPress.org popular listings
2. **Download**: Download and extract plugin ZIPs to `./plugins/`
3. **Analyze**: 4-pass analysis per plugin:
   - Pass 1: Discover hook wrapper functions (`BuildPluginWrapperRegistry`)
   - Pass 2: Build plugin-wide call graph (`BuildPluginCallGraphFromFiles`)
   - Pass 3: Detect endpoints (REST, AJAX, Admin, Framework, Wrapper calls)
   - Pass 4: Enrich endpoints with recursive call graph (`FunctionCalls` field)
4. **Classify**: Infer auth level for each endpoint
5. **Report**: Generate summary with endpoints grouped by auth level

### Validation Workflow

`validate.go` compares WPTraceLib detection against manual analysis files in `analysis-results/`. It calculates coverage metrics for REST, AJAX, and Admin endpoints.

Manual analysis files use this format:
```
Unauthenticated Endpoint List:
/wp-admin/admin-ajax.php?action=plugin_action
/wp-json/namespace/v1/route

Authenticated Endpoint List (User):
/wp-admin/admin-ajax.php?action=user_action

Authenticated Endpoint List (Admin):
wp-admin/admin.php?page=plugin-settings
```

## Code Conventions

- Regex patterns are compiled at package level (not inline) for performance
- String operations use `unsafe.String()` conversion to avoid memory copies for read-only content
- Concurrent operations use `errgroup.WithContext()` with configurable worker limits
- All endpoint detection functions take `(content, filepath, pluginSlug string)` and return `[]models.Endpoint`

### Memory Optimization Patterns

The analyzer uses several memory optimization techniques:

- **Buffer pooling**: `fileBufferPool` (sync.Pool) reuses 64KB buffers for file reads
- **Stripped content cache**: PHP content is stripped of comments once and cached for reuse across passes
- **Pre-allocated slices**: Capacity is calculated before allocation to avoid growth reallocations
- **Early cleanup**: Caches and call graphs are explicitly cleared after use to enable earlier GC

### Call Chain Modes

`ChainMode` controls call graph analysis depth and output format:

- `ChainModeNone` (default): Skips call graph analysis entirely for fastest performance
- `ChainModeFlat`: Builds flat `FunctionCalls` lists (legacy, used internally)
- `ChainModeHierarchical`: Builds nested `CallChain` trees for `-chain-human`/`-chain-json` output

---

## Proactive Plugin Agent Usage

**Use these agents automatically when the situation applies - don't wait to be asked.**

### Development Workflow Agents
- `superpowers:brainstorming` → Before any new feature/functionality
- `superpowers:test-driven-development` → Before writing implementation code
- `superpowers:systematic-debugging` → When encountering bugs or test failures
- `superpowers:writing-plans` → For multi-step tasks with requirements
- `superpowers:verification-before-completion` → Before claiming work is done
- `feature-dev:code-reviewer` → After implementing features
- `superpowers:code-reviewer` → After completing major project steps

### Analysis Agents
- `static-code-analyzer` → When reviewing for hardcoded patterns
- `performance-analyzer` → For threading/performance analysis
- `memory-optimizer` → For memory optimization opportunities
- `dead-code-eliminator` → When cleaning up after refactors

### Exploration Agents
- `Explore` (Task tool) → When searching/understanding codebase
- `feature-dev:code-explorer` → For deep feature analysis
- `feature-dev:code-architect` → When designing architectures

### Utility Agents
- `perfectionist-loop` → For exhaustive iterative refinement
- `use-context` → When needing comprehensive codebase context
- `github` → For git operations (push, commit, tag)

---

## ENFORCED WORKFLOW

**See `~/.claude/CLAUDE.md` for detailed workflow system documentation** (state machine, blocking rules, auto-marking, recovery procedures).

This project follows the global 7-step workflow with these **project-specific requirements**:

### WPTraceLib-Specific Workflow Requirements

| Step | Project-Specific Requirement |
|------|------------------------------|
| **MEMORY_CHECK** | **IMPORTANT** - This tool processes many PHP files. Check buffer pool usage and cache cleanup. |
| **SIMPLIFY** | Focus on `pkg/analyzer/` package |
| **INTERACTIVE_TEST** | **CLI tool** - verify via test suite and manual CLI testing (no Playwright needed) |

### Memory Optimization Verification

WPTraceLib uses memory optimization patterns documented in "Code Conventions" above. When marking MEMORY_CHECK complete, verify:

1. **Buffer pooling**: `fileBufferPool` is properly used for file reads
2. **Stripped content cache**: PHP content cache is cleared after use
3. **Pre-allocated slices**: Check new code uses capacity estimation
4. **Call graph cleanup**: Call graphs are explicitly cleared after analysis

Run memory-sensitive tests:
```bash
go test -bench=. ./...   # Check for performance regression
```

### Testing Verification (CLI Tool)

Since WPTraceLib is a CLI tool without a web UI, verify via:

```bash
# Run full test suite
go test ./...

# Run with race detector
go test -race ./...

# Manual CLI testing - analyze test plugins
./wptracelib -analyze ./test-plugins -stats

# Verify output formats
./wptracelib -analyze ./test-plugins -chain-human
./wptracelib -analyze ./test-plugins -chain-json
```

When testing is complete, use `superpowers:verification-before-completion` skill to mark INTERACTIVE_TEST.

### Quick Start

Use `/enforced-implementation` to run the complete workflow:
```
/enforced-implementation Add feature X
```
