package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"net/http"
	"regexp"
)

var serverRegex, _ = regexp.Compile("^([A-Za-z]+)\\/?((\\*|\\d+(\\.\\d+){0,2}(\\.\\*)?))?")
var versionRegex, _ = regexp.Compile("(\\*|\\d+(\\.\\d+){0,2}(\\.\\*)?)")

func AnalyseServer(url string, isVerbose bool) data.WebserverData {
	var webServerData data.WebserverData
	resp, err := http.Get(url)
	if err != nil {
		out.PrintError("AnalyseServer: url not reachable %s", err.Error())
		return webServerData
	}
	defer resp.Body.Close()
	serverHeader := resp.Header.Get("Server")
	poweredHeader := resp.Header.Get("X-Powered-By")

	webServerData.IsServerFound = len(serverHeader) > 0
	webServerData.ServerName = getServerHeaderProp(serverHeader, Name)
	webServerData.ServerVersion = getServerHeaderProp(serverHeader, Version)
	webServerData.IsServerVersionFound = len(webServerData.ServerVersion) > 0

	webServerData.IsTechnologyFound = len(poweredHeader) > 0
	webServerData.TechnologyName = getServerHeaderProp(poweredHeader, Name)
	webServerData.TechnologyVersion = getServerHeaderProp(poweredHeader, Version)
	webServerData.IsTechnologyVersionFound = len(webServerData.TechnologyVersion) > 0
	return webServerData
}

type ServerProperty string

const (
	Version ServerProperty = "version"
	Name    ServerProperty = "Name"
)

func getServerHeaderProp(text string, prop ServerProperty) string {
	groups := serverRegex.FindStringSubmatch(text)
	if prop == Version && len(groups) >= 3 {
		return groups[2]
	} else if prop == Name && len(groups) >= 2 {
		return groups[1]
	}
	return ""
}
