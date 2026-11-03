package store

// Warning is an advisory note for one bot field. The daemon fills it on read.
// It is not stored.
type Warning struct {
	Field string       `json:"field"`
	Text  string       `json:"text"`
	Link  *WarningLink `json:"link,omitempty"`
}

// WarningLink is an optional link shown after a warning.
type WarningLink struct {
	Href  string `json:"href"`
	Label string `json:"label"`
}
