package data

type TlsData struct {
	VersionsAvailable   []TlsVersion
	VersionsUnavailable []TlsVersion
	Domain              string
	Issuer              string
	Valid               bool
	Sha256              string
	Sha1                string
}

type TlsVersion struct {
	Name        string
	IsOutofDate bool
}
