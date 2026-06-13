package models

import "encoding/json"

// AuthLevel represents the authentication level required for an endpoint.
// WordPress has a granular role hierarchy, and we map capabilities to these levels:
//
//	SuperAdmin > Admin > Editor > Author > Contributor > Subscriber > Unauthenticated
//
// This allows accurate security research by distinguishing between different privilege levels.
type AuthLevel int

const (
	// Unauthenticated - No authentication required (public access)
	Unauthenticated AuthLevel = iota
	// Subscriber - Any logged-in user (has 'read' capability)
	Subscriber
	// Contributor - Can create content but not publish (has 'edit_posts' but not 'publish_posts')
	Contributor
	// Author - Can publish own content (has 'publish_posts', 'upload_files')
	Author
	// Editor - Can manage all content (has 'edit_others_posts', 'moderate_comments', 'manage_categories')
	Editor
	// Admin - Full site administration (has 'manage_options', 'activate_plugins', etc.)
	Admin
	// SuperAdmin - Network/multisite administration (has 'manage_network', 'manage_sites', etc.)
	SuperAdmin
)

// String returns the string representation of AuthLevel
func (a AuthLevel) String() string {
	switch a {
	case Unauthenticated:
		return "unauthenticated"
	case Subscriber:
		return "subscriber"
	case Contributor:
		return "contributor"
	case Author:
		return "author"
	case Editor:
		return "editor"
	case Admin:
		return "admin"
	case SuperAdmin:
		return "superadmin"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler
func (a AuthLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (a *AuthLevel) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "unauthenticated":
		*a = Unauthenticated
	case "subscriber":
		*a = Subscriber
	case "contributor":
		*a = Contributor
	case "author":
		*a = Author
	case "editor":
		*a = Editor
	case "admin":
		*a = Admin
	case "superadmin":
		*a = SuperAdmin
	// Backwards compatibility: "user" maps to Subscriber (lowest authenticated level)
	case "user":
		*a = Subscriber
	default:
		*a = Unauthenticated
	}
	return nil
}

// IsAuthenticated returns true if the auth level requires login
func (a AuthLevel) IsAuthenticated() bool {
	return a >= Subscriber
}

// IsAtLeast returns true if auth level is at least the specified level
func (a AuthLevel) IsAtLeast(level AuthLevel) bool {
	return a >= level
}

// EndpointType represents the type of WordPress endpoint
type EndpointType string

const (
	EndpointTypeREST      EndpointType = "rest"
	EndpointTypeAJAX      EndpointType = "ajax"
	EndpointTypeAdmin     EndpointType = "admin"
	EndpointTypeShortcode EndpointType = "shortcode"
	EndpointTypeWidget    EndpointType = "widget"
	EndpointTypeBlock     EndpointType = "block"
	EndpointTypeHookInput EndpointType = "hook_input"
	EndpointTypeDirect   EndpointType = "direct"
)

// CallChainNode represents a function call in a hierarchical call chain
// Used when -chain-human or -chain-json flags are specified
type CallChainNode struct {
	Function string           `json:"function"`
	Calls    []*CallChainNode `json:"calls,omitempty"`
}

// Endpoint represents a discovered WordPress endpoint
type Endpoint struct {
	PluginSlug string       `json:"plugin_slug"`
	Type       EndpointType `json:"type"`
	Route      string       `json:"route"`
	Method     string       `json:"method,omitempty"`
	AuthLevel  AuthLevel    `json:"auth_level"`
	Callback   string       `json:"callback"`
	File       string       `json:"file"`
	Line       int          `json:"line"`
	RawCode    string       `json:"raw_code,omitempty"`
	Namespace  string       `json:"namespace,omitempty"`
	// FunctionCalls contains the list of functions called by this endpoint's callback
	// This is populated by call graph analysis and shows the recursive call chain (flat list)
	FunctionCalls []string `json:"function_calls,omitempty"`
	// CalledBy contains functions that call this endpoint's callback (reverse lookup)
	CalledBy []string `json:"called_by,omitempty"`
	// CallChain contains the hierarchical call chain for this endpoint's callback
	// Only populated when -chain-human or -chain-json flags are used
	CallChain []*CallChainNode `json:"call_chain,omitempty"`
}

// PluginAnalysis contains the analysis results for a single plugin
type PluginAnalysis struct {
	PluginSlug     string          `json:"plugin_slug"`
	PluginName     string          `json:"plugin_name"`
	Version        string          `json:"version"`
	Endpoints      []Endpoint      `json:"endpoints"`
	FilesCount     int             `json:"files_analyzed"`
	Errors         []string        `json:"errors,omitempty"`
	CoverageReport *CoverageReport `json:"coverage_report,omitempty"`
}

// RESTCoverageGap represents a register_rest_route() call that produced no detected endpoint
type RESTCoverageGap struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	RawCode string `json:"raw_code"`
	Reason  string `json:"reason"`
}

// CoverageReport summarizes REST endpoint detection completeness
type CoverageReport struct {
	TotalRESTRouteCalls int                `json:"total_rest_route_calls"`
	DetectedEndpoints   int                `json:"detected_endpoints"`
	Gaps                []RESTCoverageGap  `json:"gaps,omitempty"`
}

// EndpointsByAuth groups endpoints by authentication level
type EndpointsByAuth struct {
	Unauthenticated []Endpoint `json:"unauthenticated"`
	Subscriber      []Endpoint `json:"subscriber"`
	Contributor     []Endpoint `json:"contributor"`
	Author          []Endpoint `json:"author"`
	Editor          []Endpoint `json:"editor"`
	Admin           []Endpoint `json:"admin"`
	SuperAdmin      []Endpoint `json:"superadmin"`
}

// Summary contains summary statistics
type Summary struct {
	TotalPlugins         int `json:"total_plugins"`
	TotalEndpoints       int `json:"total_endpoints"`
	UnauthenticatedCount int `json:"unauthenticated_count"`
	SubscriberCount      int `json:"subscriber_count"`
	ContributorCount     int `json:"contributor_count"`
	AuthorCount          int `json:"author_count"`
	EditorCount          int `json:"editor_count"`
	AdminCount           int `json:"admin_count"`
	SuperAdminCount      int `json:"superadmin_count"`
	RESTCount            int `json:"rest_count"`
	AJAXCount            int `json:"ajax_count"`
	AdminPagesCount      int `json:"admin_pages_count"`
	ShortcodeCount       int `json:"shortcode_count"`
	WidgetCount          int `json:"widget_count"`
	BlockCount           int `json:"block_count"`
	HookInputCount       int `json:"hook_input_count"`
	DirectCount          int `json:"direct_count"`
}

// AuthenticatedCount returns total count of endpoints requiring authentication
func (s Summary) AuthenticatedCount() int {
	return s.SubscriberCount + s.ContributorCount + s.AuthorCount + s.EditorCount + s.AdminCount + s.SuperAdminCount
}

// FullReport contains the complete analysis report
type FullReport struct {
	Plugins   []PluginInfo    `json:"plugins"`
	Endpoints EndpointsByAuth `json:"endpoints"`
	Summary   Summary         `json:"summary"`
}

// SortEndpointsByAuth categorizes endpoints by their authentication level
func SortEndpointsByAuth(endpoints []Endpoint) EndpointsByAuth {
	result := EndpointsByAuth{
		Unauthenticated: make([]Endpoint, 0),
		Subscriber:      make([]Endpoint, 0),
		Contributor:     make([]Endpoint, 0),
		Author:          make([]Endpoint, 0),
		Editor:          make([]Endpoint, 0),
		Admin:           make([]Endpoint, 0),
		SuperAdmin:      make([]Endpoint, 0),
	}

	for _, ep := range endpoints {
		switch ep.AuthLevel {
		case Unauthenticated:
			result.Unauthenticated = append(result.Unauthenticated, ep)
		case Subscriber:
			result.Subscriber = append(result.Subscriber, ep)
		case Contributor:
			result.Contributor = append(result.Contributor, ep)
		case Author:
			result.Author = append(result.Author, ep)
		case Editor:
			result.Editor = append(result.Editor, ep)
		case Admin:
			result.Admin = append(result.Admin, ep)
		case SuperAdmin:
			result.SuperAdmin = append(result.SuperAdmin, ep)
		}
	}

	return result
}

// CalculateSummary generates summary statistics from plugin analyses
func CalculateSummary(plugins []PluginInfo, analyses []PluginAnalysis) Summary {
	summary := Summary{
		TotalPlugins: len(plugins),
	}

	for _, analysis := range analyses {
		for _, ep := range analysis.Endpoints {
			summary.TotalEndpoints++

			switch ep.AuthLevel {
			case Unauthenticated:
				summary.UnauthenticatedCount++
			case Subscriber:
				summary.SubscriberCount++
			case Contributor:
				summary.ContributorCount++
			case Author:
				summary.AuthorCount++
			case Editor:
				summary.EditorCount++
			case Admin:
				summary.AdminCount++
			case SuperAdmin:
				summary.SuperAdminCount++
			}

			switch ep.Type {
			case EndpointTypeREST:
				summary.RESTCount++
			case EndpointTypeAJAX:
				summary.AJAXCount++
			case EndpointTypeAdmin:
				summary.AdminPagesCount++
			case EndpointTypeShortcode:
				summary.ShortcodeCount++
			case EndpointTypeWidget:
				summary.WidgetCount++
			case EndpointTypeBlock:
				summary.BlockCount++
			case EndpointTypeHookInput:
				summary.HookInputCount++
			case EndpointTypeDirect:
				summary.DirectCount++
			}
		}
	}

	return summary
}
