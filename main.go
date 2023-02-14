package main

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"SiteSecurityCheck/scan"
	"flag"
)

func main() {
	//check arguments
	var cveApiKey string
	var locationApiKey string
	var websiteURL string
	var format out.Format
	flag.StringVar(&websiteURL, "u", "", "URL of the website to scan")
	flag.StringVar(&cveApiKey, "cve", "", "API Key for the CVE API")
	flag.StringVar(&locationApiKey, "loc", "", "API Key for the Location API")
	flag.StringVar((*string)(&format), "f", "human", "Format of the output. Available values: 'json'= JSON of the result, 'human'= human readable format")
	flag.Parse()
	if len(websiteURL) < 3 {
		print("flag -u must be filled with a valid website URL. Use -h to get a list of all available flags")
		return
	}
	if !out.CheckFormat(format) {
		return
	}

	//start scanning
	var res = data.ScanResult{}
	out.PrintScanTitle(websiteURL, format)
	res.Ports = scan.StartPortScan(websiteURL)
	//output result
	out.PrintResult(res, format)

}
