package data

type ScanResult struct {
	ScanUrl             string
	CveApiProvided      bool
	LocationApiProvided bool
	Tls                 TlsData
	Server              WebserverData
	Cms                 CmsData
	Headers             []HeaderData
	Vulnerabilities     []CveData
	Ports               []FoundPort
	Miscellaneous       MiscellaneousData
}
