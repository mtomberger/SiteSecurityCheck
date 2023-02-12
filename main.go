package main

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"flag"
	"github.com/schollz/progressbar/v3"
	"time"
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
	out.PrintScanTitle(websiteURL, format)
	bar := progressbar.Default(-1)
	for i := 0; i < 100; i++ {
		bar.Add(0)
		time.Sleep(40 * time.Millisecond)
	}
	var x = data.MiscellaneousData{
		Cookies:        nil,
		UseCloudflare:  false,
		ServerIp:       "564.654.646.64",
		ServerLocation: "Wakanda",
		ServerHosted:   "Ich",
	}
	x.ServerIp = "fdsg"
	var res = data.ScanResult{
		Miscellaneous: x,
	}
	//output result
	out.PrintResult(res, format)

}
