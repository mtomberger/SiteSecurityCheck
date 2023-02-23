package data

type HeaderData struct {
	HeaderName string
	DocLink    string
	IsSet      bool
	Rating     HeaderRating
}
type HeaderRating struct {
	Rating      int
	Description string
}
