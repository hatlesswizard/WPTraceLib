package analyzer

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hatlesswizard/wptracelib/pkg/models"
)

var coverageRestRouteCallPattern = regexp.MustCompile(`register_rest_route\s*\(`)

// AuditRESTCoverage compares detected REST endpoints against register_rest_route() calls
// in the stripped source code. Any call that produced no matching endpoint is reported as a gap.
func AuditRESTCoverage(pluginDir string, endpoints []models.Endpoint, strippedCache map[string]string) *models.CoverageReport {
	report := &models.CoverageReport{}

	// Build a set of (file, line) pairs from detected REST endpoints (with ±3 line tolerance)
	type fileLine struct {
		file string
		line int
	}
	detected := make(map[fileLine]bool)
	for _, ep := range endpoints {
		// Only handler endpoints. A permission-callback endpoint carries its
		// callback's DECLARATION line, not the registration line, so counting it
		// here would let a declaration that happens to sit within the audit's
		// three-line tolerance of an unparsed register_rest_route call mask a
		// real gap.
		if ep.Type != models.EndpointTypeREST {
			continue
		}
		report.DetectedEndpoints++
		// An endpoint's File comes from makeRelativePath, i.e. filepath.Rel, so on
		// Windows it carries backslashes ("src\Controllers\Routes.php") while the
		// scan below builds its key with filepath.ToSlash. Comparing the two forms
		// directly meant every endpoint in a SUBDIRECTORY failed to match its own
		// register_rest_route call and was reported as a gap. Measured before this
		// line was added: suretriggers 1.0.78 reported "10 route calls -> 10
		// endpoints, 10 gaps", listing as uncovered the ten calls whose endpoints it
		// had just printed, and lifterlms 9.1.0 reported all 9 of its calls as gaps.
		// Both lists were 100% false positives. Normalise both sides.
		file := filepath.ToSlash(ep.File)
		for delta := -3; delta <= 3; delta++ {
			detected[fileLine{file: file, line: ep.Line + delta}] = true
		}
	}

	// Scan each cached file for register_rest_route() calls
	for absPath, content := range strippedCache {
		var relPath string
		if pluginDir != "" {
			var err error
			relPath, err = filepath.Rel(pluginDir, absPath)
			if err != nil {
				relPath = absPath
			}
		} else {
			relPath = absPath
		}
		relPath = filepath.ToSlash(relPath)

		matches := coverageRestRouteCallPattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			pos := match[0]
			lineNum := strings.Count(content[:pos], "\n") + 1
			report.TotalRESTRouteCalls++

			// Check if any detected endpoint matches this position
			if detected[fileLine{file: relPath, line: lineNum}] {
				continue
			}

			// Classify the gap reason
			reason := classifyGapReason(content, pos)

			// Extract code snippet for context
			snippetEnd := pos + 200
			if snippetEnd > len(content) {
				snippetEnd = len(content)
			}
			rawCode := content[pos:snippetEnd]
			if nlIdx := strings.Index(rawCode, "\n"); nlIdx > 0 {
				// Include a few lines for context
				for i, count := 0, 0; i < len(rawCode) && count < 3; i++ {
					if rawCode[i] == '\n' {
						count++
						if count == 3 {
							rawCode = rawCode[:i]
						}
					}
				}
			}

			report.Gaps = append(report.Gaps, models.RESTCoverageGap{
				File:    relPath,
				Line:    lineNum,
				RawCode: strings.TrimSpace(rawCode),
				Reason:  reason,
			})
		}
	}

	// strippedCache is a map, so the scan above visits files in a random order and
	// the gap list came out in a different order on every run. A report that is
	// read by a human or diffed between two runs has to be stable, so sort it.
	sort.Slice(report.Gaps, func(i, j int) bool {
		if report.Gaps[i].File != report.Gaps[j].File {
			return report.Gaps[i].File < report.Gaps[j].File
		}
		return report.Gaps[i].Line < report.Gaps[j].Line
	})

	return report
}

// classifyGapReason determines why a register_rest_route() call was not detected
func classifyGapReason(content string, pos int) string {
	// Look at the surrounding context (200 chars before the call)
	contextStart := pos - 200
	if contextStart < 0 {
		contextStart = 0
	}
	before := content[contextStart:pos]

	// Check if inside a closure (wrapper pattern)
	if strings.Contains(before, "function") && strings.Contains(before, "use") {
		return "wrapper_pattern"
	}

	// Check if arguments are all variables (dynamic)
	afterEnd := pos + 500
	if afterEnd > len(content) {
		afterEnd = len(content)
	}
	after := content[pos:afterEnd]
	if strings.Count(after[:min(100, len(after))], "$") >= 3 {
		return "dynamic_args"
	}

	return "complex_expression"
}
