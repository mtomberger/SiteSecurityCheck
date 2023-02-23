package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

const ApiUrl = "https://vuldb.com/?api"
const LookupUrl = "https://nvd.nist.gov/vuln/detail/"

func GetVulnerabilities(result data.ScanResult, apiKey string, limit int) []data.CveData {
	if len(apiKey) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	l := sync.Mutex{}
	var vulnerabilities []data.CveData
	if result.Server.IsServerFound {
		vers := ""
		if result.Server.IsServerVersionFound {
			vers = result.Server.ServerVersion
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := getVulnerabilitiesForProduct(result.Server.ServerName, vers, apiKey, limit)
			l.Lock()
			vulnerabilities = append(vulnerabilities, vulns...)
			l.Unlock()
		}()
	}
	if result.Server.IsTechnologyFound {
		vers := ""
		if result.Server.IsTechnologyVersionFound {
			vers = result.Server.TechnologyVersion
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := getVulnerabilitiesForProduct("php", vers, apiKey, limit)
			l.Lock()
			vulnerabilities = append(vulnerabilities, vulns...)
			l.Unlock()
		}()
	}
	if result.Cms.CmsFound {
		vers := ""
		if result.Cms.VersionFound {
			vers = result.Cms.Version
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns := getVulnerabilitiesForProduct(result.Cms.Name, vers, apiKey, limit)
			l.Lock()
			vulnerabilities = append(vulnerabilities, vulns...)
			l.Unlock()
		}()
	}
	wg.Wait()
	return vulnerabilities
}
func getVulnerabilitiesForProduct(product string, version string, apiKey string, limit int) []data.CveData {
	var vulnDbResponse VulDbResponse
	var cveData []data.CveData
	searchStr := "advancedsearch=" + url.QueryEscape("product:"+product+",version:"+version)
	if limit > 0 {
		searchStr += "&limit=" + strconv.Itoa(limit)
	}
	r, err := http.NewRequest("POST", ApiUrl, bytes.NewBuffer([]byte(searchStr)))
	if err != nil {
		out.PrintError("getVulnerabilitiesForProduct: Request creation failed %s", err.Error())
		return nil
	}
	r.Header.Add("X-VulDB-ApiKey", apiKey)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(r)
	defer resp.Body.Close()
	if err != nil {
		out.PrintError("getVulnerabilitiesForProduct: Request failed " + err.Error())
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		out.PrintError("getVulnerabilitiesForProduct: Reading response failed " + err.Error())
	}
	err = json.Unmarshal(body, &vulnDbResponse)
	if err != nil {
		out.PrintError("getVulnerabilitiesForProduct: parsing response failed" + err.Error())
	}
	if vulnDbResponse.Response.Status != "200" {
		out.PrintError("getVulnerabilitiesForProduct: VulDb response error: " + vulnDbResponse.Response.Error + "(" + vulnDbResponse.Response.Status + ")")
		return cveData
	}
	for _, vu := range vulnDbResponse.Result {
		cveData = append(cveData, data.CveData{
			Id:           vu.Source.Cve.ID,
			Name:         vu.Entry.Title,
			Url:          LookupUrl + vu.Source.Cve.ID,
			Risk:         vu.Vulnerability.Risk.Value,
			RiskName:     vu.Vulnerability.Risk.Name,
			SearchString: product + " " + version,
		})
	}
	return cveData
}

// vuldb response struct
type VulDbResponse struct {
	Response struct {
		Version       string `json:"version"`
		Format        string `json:"format"`
		Status        string `json:"status"`
		Error         string `json:"error"`
		Lang          string `json:"lang"`
		Monoblock     string `json:"monoblock"`
		Items         int    `json:"items"`
		Consumption   int    `json:"consumption"`
		Remaining     int    `json:"remaining"`
		Querylimit    int    `json:"querylimit"`
		Querylimitmax int    `json:"querylimitmax"`
		Timestamp     string `json:"timestamp"`
		Rtt           int    `json:"rtt"`
		Etag          string `json:"etag"`
	} `json:"response"`
	Request struct {
		Timestamp string `json:"timestamp"`
		Apikey    string `json:"apikey"`
		Userid    string `json:"userid"`
		Details   int    `json:"details"`
		Sort      string `json:"sort"`
		Cti       int    `json:"cti"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"request"`
	Result []struct {
		Entry struct {
			ID        string `json:"id"`
			Title     string `json:"title"`
			Timestamp struct {
				Create string `json:"create"`
				Change string `json:"change"`
			} `json:"timestamp"`
		} `json:"entry"`
		Vulnerability struct {
			Risk struct {
				Value string `json:"value"`
				Name  string `json:"name"`
			} `json:"risk"`
		} `json:"vulnerability"`
		Advisory struct {
			Date string `json:"date"`
		} `json:"advisory"`
		Source struct {
			Cve struct {
				ID string `json:"id"`
			} `json:"cve"`
		} `json:"source"`
	} `json:"result"`
}
