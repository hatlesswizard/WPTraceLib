package analyzer

import (
	"path/filepath"
	"regexp"
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
		if ep.Type != models.EndpointTypeREST {
			continue
		}
		report.DetectedEndpoints++
		for delta := -3; delta <= 3; delta++ {
			detected[fileLine{file: ep.File, line: ep.Line + delta}] = true
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
