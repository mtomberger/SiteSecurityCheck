package data

import "time"

type TlsData struct {
	VersionsAvailable   []TlsVersion
	VersionsUnavailable []TlsVersion
	RawCertInfo         string
	Issuer              string
	Subject             string
	Valid               bool
	NotBefore           time.Time
	NotAfter            time.Time
}

type TlsVersion struct {
	Name        string
	IsOutOfDate bool
	Id          uint16
}
