package data

// Strict-Transport-Security, Content-Security-Policy,X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
type HeaderData struct {
	HeaderName    string
	IsSet         bool
	ContentRating string
}
