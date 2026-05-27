package models

import "encoding/json"

// FlexString handles JSON fields that can be string or bool
// WordPress API returns false for fields like requires_php when not set
type FlexString string

// UnmarshalJSON implements json.Unmarshaler for FlexString
func (f *FlexString) UnmarshalJSON(data []byte) error {
	// Handle boolean false/true
	if string(data) == "false" || string(data) == "true" {
		*f = ""
		return nil
	}
	// Handle null
	if string(data) == "null" {
		*f = ""
		return nil
	}
	// Handle string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// If parsing fails, return empty string rather than error
		*f = ""
		return nil
	}
	*f = FlexString(s)
	return nil
}

// String returns the string value
func (f FlexString) String() string {
	return string(f)
}

// FlexMap handles JSON fields that can be map[string]string or empty array
// WordPress API returns [] for empty tags/sections instead of {} or null
type FlexMap map[string]string

// UnmarshalJSON implements json.Unmarshaler for FlexMap
func (f *FlexMap) UnmarshalJSON(data []byte) error {
	// Handle null
	if string(data) == "null" {
		*f = nil
		return nil
	}
	// Handle empty array []
	if string(data) == "[]" {
		*f = make(map[string]string)
		return nil
	}
	// Try to unmarshal as map
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		// If it fails, return empty map rather than error
		*f = make(map[string]string)
		return nil
	}
	*f = m
	return nil
}

// PluginInfo contains metadata about a WordPress plugin
type PluginInfo struct {
	Slug                string `json:"slug"`
	Name                string `json:"name"`
	Version             string `json:"version"`
	ActiveInstallations string `json:"active_installations"`
	DownloadURL         string `json:"download_link"`
	TestedUpTo          string `json:"tested"`
	RequiresPHP         string `json:"requires_php"`
	RequiresWP          string `json:"requires"`
	Author              string `json:"author"`
	AuthorProfile       string `json:"author_profile"`
	Rating              int    `json:"rating"`
	NumRatings          int    `json:"num_ratings"`
	Downloaded          int64  `json:"downloaded"`
	LastUpdated         string `json:"last_updated"`
	Homepage            string `json:"homepage"`
	ShortDescription    string `json:"short_description"`
}

// PluginAPIResponse represents the response from WordPress Plugin API
type PluginAPIResponse struct {
	Slug                string            `json:"slug"`
	Name                string            `json:"name"`
	Version             string            `json:"version"`
	ActiveInstallations int               `json:"active_installs"`
	DownloadLink        string            `json:"download_link"`
	Tested              FlexString        `json:"tested"`
	RequiresPHP         FlexString        `json:"requires_php"`
	Requires            FlexString        `json:"requires"`
	Author              string            `json:"author"`
	AuthorProfile       string            `json:"author_profile"`
	Rating              int               `json:"rating"`
	NumRatings          int               `json:"num_ratings"`
	Downloaded          int64             `json:"downloaded"`
	LastUpdated         string            `json:"last_updated"`
	Homepage            string            `json:"homepage"`
	ShortDescription    string            `json:"short_description"`
	Sections            FlexMap `json:"sections"`
	Tags                FlexMap `json:"tags"`
}

// ToPluginInfo converts API response to PluginInfo
func (r *PluginAPIResponse) ToPluginInfo() PluginInfo {
	return PluginInfo{
		Slug:                r.Slug,
		Name:                r.Name,
		Version:             r.Version,
		ActiveInstallations: formatInstallations(r.ActiveInstallations),
		DownloadURL:         r.DownloadLink,
		TestedUpTo:          r.Tested.String(),
		RequiresPHP:         r.RequiresPHP.String(),
		RequiresWP:          r.Requires.String(),
		Author:              r.Author,
		AuthorProfile:       r.AuthorProfile,
		Rating:              r.Rating,
		NumRatings:          r.NumRatings,
		Downloaded:          r.Downloaded,
		LastUpdated:         r.LastUpdated,
		Homepage:            r.Homepage,
		ShortDescription:    r.ShortDescription,
	}
}

// formatInstallations converts numeric installations to human-readable format
func formatInstallations(count int) string {
	switch {
	case count >= 10000000:
		return "10+ million"
	case count >= 5000000:
		return "5+ million"
	case count >= 1000000:
		return "1+ million"
	case count >= 500000:
		return "500,000+"
	case count >= 100000:
		return "100,000+"
	case count >= 50000:
		return "50,000+"
	case count >= 30000:
		return "30,000+"
	case count >= 20000:
		return "20,000+"
	case count >= 10000:
		return "10,000+"
	case count >= 1000:
		return "1,000+"
	case count >= 100:
		return "100+"
	case count >= 10:
		return "10+"
	default:
		return "Less than 10"
	}
}
