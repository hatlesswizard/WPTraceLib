# WPTraceLib

A Go-based static analysis tool for WordPress plugin security research. WPTraceLib scans
WordPress plugins to discover API endpoints (REST, AJAX, and Admin pages) and classifies
each one by the authentication level required to reach it.

Endpoints are categorized along the WordPress role hierarchy:

```
SuperAdmin > Admin > Editor > Author > Contributor > Subscriber > Unauthenticated
```

## Features

- Static PHP analysis — no plugin code is executed
- Detects REST API routes (`register_rest_route`), AJAX handlers (`wp_ajax_*` / `wp_ajax_nopriv_*`), and admin menu pages
- Infers the required authentication level from capability checks and permission callbacks
- Recognizes framework patterns (WooCommerce, ACF, Elementor) and plugin-specific hook wrappers
- Optional call-chain analysis from each endpoint callback
- Usable both as a CLI tool and as a Go library

## Requirements

- Go 1.25 or newer

## Installation

```bash
git clone https://github.com/hatlesswizard/WPTraceLib.git
cd WPTraceLib
go build ./cmd/wptracelib
```

This produces a `wptracelib` binary (`wptracelib.exe` on Windows).

## Usage

```bash
# Analyze plugins already on disk (auto-detects single vs. multi-plugin directories)
./wptracelib -analyze ./plugins
./wptracelib -analyze ./plugins/contact-form-7

# Download and analyze popular plugins from WordPress.org (first 5 pages)
./wptracelib -pages 5 -output ./plugins

# Stop after 25 successfully resolved plugins (0 means all)
./wptracelib -plugins 25 -output ./plugins

# Page and plugin limits are independent; the first exhausted boundary wins
./wptracelib -pages 5 -plugins 25 -output ./plugins

# Show statistics only
./wptracelib -analyze ./plugins -stats

# Filter by authentication level
./wptracelib -analyze ./plugins -unauth        # unauthenticated only
./wptracelib -analyze ./plugins -auth          # all authenticated (subscriber+)
./wptracelib -analyze ./plugins -admin         # admin-level only
# (also: -subscriber, -contributor, -author, -editor, -superadmin)

# Save output to a file
./wptracelib -analyze ./plugins -save report.txt

# List popular plugins without downloading
./wptracelib -list-only

# Call-chain analysis
./wptracelib -analyze ./plugins -chain-human   # tree format
./wptracelib -analyze ./plugins -chain-json    # JSON with nested call chains
```

Run `./wptracelib -h` for the full flag list.

## Library usage

```go
import (
    "context"
    "net/http"

    "github.com/hatlesswizard/wptracelib"
    "github.com/hatlesswizard/wptracelib/pkg/analyzer"
)

func main() {
    cfg := wptracelib.Config{
        OutputDir: "./plugins",
        Workers:    10,
        MaxPages:   0,  // all popular-plugin pages
        MaxPlugins: 0,  // all successfully resolved plugins
        ChainMode:  analyzer.ChainModeHierarchical, // or ChainModeNone, ChainModeFlat

        // Optional: called for every HTTP attempt (popular pages, plugin
        // details, and ZIP downloads), so callers can rotate transports/proxies.
        // Nil uses WPTraceLib's default direct clients.
        HTTPClientFactory: func() *http.Client {
            return http.DefaultClient
        },
    }
    lib := wptracelib.New(cfg)

    ctx := context.Background()

    // Analyze a directory of plugins
    analyses, err := lib.AnalyzeDirectory(ctx, "./plugins")
    _ = analyses
    _ = err

    // Or run the full workflow: fetch, download, analyze
    // report, err := lib.Run(ctx)
}
```

## Testing

```bash
go test ./...
go test -race ./...
go test -cover ./...
```

## License

Licensed under the [GNU General Public License v3.0](LICENSE).
