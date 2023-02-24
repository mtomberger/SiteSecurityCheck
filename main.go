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
	"sync"
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
	//init scan object
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
	//print header of output
	out.PrintScanTitle(websiteURL, format)
	//start scanning
	var wg sync.WaitGroup
	var isCloudflare bool
	//scan part 1
	wg.Add(3)
	go func() {
		defer wg.Done()
		res.Tls = scan.TlsCheck(domain, isVerbose, config)
	}()
	go func() {
		defer wg.Done()
		res.Miscellaneous = scan.FillHostInformation(domain, locationApiKey)
	}()
	go func() {
		defer wg.Done()
		isCloudflare = scan.IsCloudflare(domain, config)
	}()
	if !res.Miscellaneous.UseCloudflare {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.Ports = scan.StartPortScan(domain, config)
		}()
	}
	wg.Wait()
	//set and rewrite values from scan part 1
	res.Miscellaneous.UseCloudflare = isCloudflare
	if !res.Tls.HttpsAvailable && strings.HasPrefix(websiteURL, "https://") {
		websiteURL = strings.Replace(websiteURL, "https://", "http://", 1)
	}
	//scan part 2
	wg.Add(3)
	go func() {
		defer wg.Done()
		res.Headers = scan.AnalyzeHeaders(websiteURL, isVerbose)
	}()
	go func() {
		defer wg.Done()
		res.Server = scan.AnalyseServer(websiteURL, isVerbose)
	}()
	go func() {
		defer wg.Done()
		res.Cms = scan.AnalyseCms(websiteURL, isVerbose, config)
	}()
	wg.Wait()
	//get Vulnerabilities from db
	res.Vulnerabilities = scan.GetVulnerabilities(res, cveApiKey, cveLimit)

	//output result
	out.PrintResult(res, config, format)

}
