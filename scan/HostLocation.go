package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type LocationApiResult struct {
	Response        string  `json:"response"`
	CountryCode     string  `json:"country_code"`
	CountryName     string  `json:"country_name"`
	RegionName      string  `json:"region_name"`
	CityName        string  `json:"city_name"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
	Isp             string  `json:"isp"`
	CreditsConsumed int     `json:"credits_consumed"`
}

func FillHostInformation(url string, apiKey string) data.MiscellaneousData {
	var locRes LocationApiResult
	var info data.MiscellaneousData
	ipaddr := getIp(url)

	info.ServerIp = ipaddr

	if len(apiKey) < 1 {
		return info
	}
	resp, err := http.Get("https://api.ip2location.com/v2/?ip=" + ipaddr + "&key=" + apiKey + "&package=WS6")
	if err != nil {
		out.PrintError("FillHostInformation: " + err.Error())
		return info
	}

	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(resp.Body)
		err = json.Unmarshal(body, &locRes)
		if err != nil {
			out.PrintError("FillHostInformation: " + err.Error())
			return info
		}
		info.ServerLocation = locRes.CountryName + fmt.Sprint(" (lat:", locRes.Latitude) + fmt.Sprint(" long:", locRes.Longitude) + ")"
		info.ServerHosted = locRes.Isp
	}
	return info
}
