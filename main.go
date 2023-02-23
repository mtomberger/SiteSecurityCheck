package main

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"SiteSecurityCheck/scan"
	"SiteSecurityCheck/utility"
	"flag"
	"net/url"
	"os"
	"strings"
)

func main() {
	//check arguments
	var cveApiKey string
	var locationApiKey string
	var websiteURL string
	var configFile string
	var isVerbose bool
	var cveLimit int
	var format out.Format
	flag.StringVar(&websiteURL, "u", "", "URL of the website to scan")
	flag.BoolVar(&isVerbose, "v", false, "Verbose. Print additional information")
	flag.StringVar(&configFile, "conf", "config/scanConfig.json", "path to configuration file (default: config/scanConfig.json))")
	flag.StringVar(&cveApiKey, "cve", "", "API Key for the CVE API (https://vuldb.com/)")
	flag.IntVar(&cveLimit, "cveL", 0, "Limit the requested CVE entries")
	flag.StringVar(&locationApiKey, "loc", "", "API Key for the Location API (https://www.ip2location.com/)")
	flag.StringVar((*string)(&format), "f", "human", "Format of the output. Available values: 'json'= JSON of the result, 'human'= human readable format")
	flag.Parse()
	if len(websiteURL) < 3 {
		out.Print(out.ColorText("flag -u must be filled with a valid website URL. Use -h to get a list of all available flags", "red"))
		out.Print(out.ColorText("Example: %s -u https://example.com -v -f json -loc l0c4710n4p1k3y -cve c0mm0nvuln3r4b1l171353xp05ur354p1k3y -cveL 5", "green", os.Args[0]))
		return
	}
	if !out.CheckFormat(format) {
		return
	}
	//validate url
	url, err := url.Parse(websiteURL)
	if err != nil {
		out.Print("%s is not a valid url: " + err.Error())
		return
	}
	domain := url.Hostname()
	//get config
	config := utility.GetConfiguration(configFile)
	//start scanning
	var res = data.ScanResult{
		ScanUrl:             websiteURL,
		LocationApiProvided: len(locationApiKey) > 0,
		CveApiProvided:      len(cveApiKey) > 0,
		Tls:                 data.TlsData{},
		Server:              data.WebserverData{},
		Cms:                 data.CmsData{},
		Headers:             []data.HeaderData{},
		Vulnerabilities:     []data.CveData{},
		Ports:               []data.FoundPort{},
		Miscellaneous:       data.MiscellaneousData{},
	}
	out.PrintScanTitle(websiteURL, format)
	res.Tls = scan.TlsCheck(domain, isVerbose, config)
	if !res.Tls.HttpsAvailable && strings.HasPrefix(websiteURL, "https://") {
		websiteURL = strings.Replace(websiteURL, "https://", "http://", 1)
	}
	res.Miscellaneous = scan.FillHostInformation(domain, locationApiKey)
	res.Miscellaneous.UseCloudflare = scan.IsCloudflare(domain)
	if !res.Miscellaneous.UseCloudflare {
		res.Ports = scan.StartPortScan(domain, config)
	}
	res.Headers = scan.AnalyzeHeaders(websiteURL, isVerbose)
	res.Server = scan.AnalyseServer(websiteURL, isVerbose)
	res.Cms = scan.AnalyseCms(websiteURL, isVerbose)
	res.Vulnerabilities = scan.GetVulnerabilities(res, cveApiKey, cveLimit)
	//output result
	out.PrintResult(res, format)

}
