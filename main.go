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
	if !config.IsReady {
		out.PrintError("No configuration found in %s", configFile)
		return
	}
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
	//test connection
	s := out.CreateStatus("Testing connection", false, format)
	if !scan.TestConnection(websiteURL, domain) {
		out.Print(out.ColorText("Url not reachable: %s", "red", websiteURL))
		s.Finish()
		return
	}
	s.Finish()
	//start scanning
	var wg sync.WaitGroup
	var isCloudflare bool
	//scan part 1
	wg.Add(3)
	tlsBar := out.CreateStatus("Check TLS", true, format)
	go func() {
		defer wg.Done()
		res.Tls = scan.TlsCheck(domain, isVerbose, config)
		tlsBar.Finish()
	}()
	locationBar := out.CreateStatus("Getting Server Location", true, format)
	go func() {
		defer wg.Done()
		res.Miscellaneous = scan.FillHostInformation(domain, locationApiKey)
		locationBar.Finish()
	}()
	cfBar := out.CreateStatus("Check for Cloudflare", true, format)
	go func() {
		defer wg.Done()
		isCloudflare = scan.IsCloudflare(domain, config)
		cfBar.Finish()
	}()
	if !res.Miscellaneous.UseCloudflare {
		wg.Add(1)
		portsBar := out.CreateStatus("Executing Portscan", true, format)
		go func() {
			defer wg.Done()
			res.Ports = scan.StartPortScan(domain, config)
			portsBar.Finish()
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
	headerBar := out.CreateStatus("Analysing HTTP Headers", true, format)
	go func() {
		defer wg.Done()
		res.Headers = scan.AnalyzeHeaders(websiteURL, isVerbose)
		headerBar.Finish()
	}()
	serverBar := out.CreateStatus("Analysing Server Properties", true, format)
	go func() {
		defer wg.Done()
		res.Server = scan.AnalyseServer(websiteURL, isVerbose)
		serverBar.Finish()
	}()
	cmsBar := out.CreateStatus("Analysing Content Management System Properties", true, format)
	go func() {
		defer wg.Done()
		res.Cms = scan.AnalyseCms(websiteURL, isVerbose, config)
		cmsBar.Finish()
	}()
	wg.Wait()
	vulBar := out.CreateStatus("Getting Vulnerabilities", false, format)
	//get Vulnerabilities from db
	res.Vulnerabilities = scan.GetVulnerabilities(res, cveApiKey, cveLimit)
	vulBar.Finish()
	//output result
	out.PrintResult(res, config, format)

}

//-u http://alfright.eu -v -f human -loc 0H1TFS9ACE2 -cve 0fc5074cb7f09126ea37257c7ad967210 -cveL 10
