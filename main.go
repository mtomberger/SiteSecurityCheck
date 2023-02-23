package main

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"SiteSecurityCheck/scan"
	"flag"
	"github.com/schollz/progressbar/v3"
	"net/url"
)

func main() {
	//check arguments
	var cveApiKey string
	var locationApiKey string
	var websiteURL string
	var isVerbose bool
	var format out.Format
	flag.StringVar(&websiteURL, "u", "", "URL of the website to scan")
	flag.BoolVar(&isVerbose, "v", false, "Verbose. Print additional information")
	flag.StringVar(&cveApiKey, "cve", "", "API Key for the CVE API")
	flag.StringVar(&locationApiKey, "loc", "", "API Key for the Location API")
	flag.StringVar((*string)(&format), "f", "human", "Format of the output. Available values: 'json'= JSON of the result, 'human'= human readable format")
	flag.Parse()
	if len(websiteURL) < 3 {
		out.Print("flag -u must be filled with a valid website URL. Use -h to get a list of all available flags")
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
	//start scanning
	var res = data.ScanResult{
		ScanUrl:         websiteURL,
		Tls:             data.TlsData{},
		Server:          data.WebserverData{},
		Cms:             data.CmsData{},
		Headers:         []data.HeaderData{},
		Vulnerabilities: []data.CveData{},
		Ports:           []data.FoundPort{},
		Miscellaneous:   data.MiscellaneousData{},
	}
	out.PrintScanTitle(websiteURL, format)
	var p = progressbar.Default(-1, "Getting Geolocation...")
	res.Miscellaneous = scan.FillHostInformation(domain, locationApiKey)
	p.Finish()
	p = progressbar.Default(-1, "Checking for Cloudflare IPs...")
	res.Miscellaneous.UseCloudflare = scan.IsCloudflare(domain)
	p.Finish()
	if !res.Miscellaneous.UseCloudflare {
		p = progressbar.Default(-1, "Executing portscan...")
		res.Ports = scan.StartPortScan(domain)
		p.Finish()
	}
	p = progressbar.Default(-1, "Getting TLS information...")
	res.Tls = scan.TlsCheck(domain)
	p.Finish()
	p = progressbar.Default(-1, "Analysing HTTP headers...")
	res.Headers = scan.AnalyzeHeaders(websiteURL)
	p.Finish()

	if !isVerbose {
		res.Tls.RawCertInfo = ""
		/*for _,h := range res.Headers{
			h.DocLink = ""
			h.Rating.Description = ""
		}*/
	}
	//output result
	out.PrintResult(res, format)

}
