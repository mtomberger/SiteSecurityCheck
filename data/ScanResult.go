package data

type ScanResult struct {
	ScanUrl         string
	Tls             TlsData
	Server          WebserverData
	Cms             CmsData
	Headers         []HeaderData
	Vulnerabilities []CveData
	Ports           []FoundPort
	Miscellaneous   MiscellaneousData
}
