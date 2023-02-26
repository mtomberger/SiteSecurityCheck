package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"SiteSecurityCheck/utility"
	"net/http"
	"regexp"
	"sync"
)

var versionRegex, _ = regexp.Compile("(\\*|\\d+(\\.\\d+){0,2}(\\.\\*)?)")

func AnalyseCms(url string, isVerbose bool, conf utility.ScanConfig) data.CmsData {
	var cmsData data.CmsData
	cmsData.CmsFound = false
	resp, err := http.Get(url)
	if err != nil {
		out.PrintError("AnalyseCms: url not reachable %s", err.Error())
		return cmsData
	}
	defer resp.Body.Close()
	// Read the HTML content of the website
	bodyBytes := make([]byte, 0, 1024*1024)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n == 0 {
			break
		}
		if err != nil {
			out.PrintError("AnalyseCms: Error when reading body %s", err.Error())
			return cmsData
		}
		bodyBytes = append(bodyBytes, buf[:n]...)
	}
	foundCms, version := searchCms(&bodyBytes, conf.Cms)
	//search for CMS
	if !foundCms.IsReady {
		return cmsData
	}
	cmsData.Name = foundCms.Name
	cmsData.CmsFound = true
	if len(version) > 0 {
		cmsData.Version = version
		cmsData.VersionFound = true
	}
	//search for plugins
	cmsData.Plugins = searchPlugins(&bodyBytes, foundCms)
	//search for reachable urls
	cmsData.ReachableUrls = searchReachableUrls(url, foundCms.Urls, conf.Threads)
	return cmsData
}
func searchReachableUrls(base string, paths []string, threads int) []string {
	var availableUrls []string
	l := sync.Mutex{}
	sem := make(chan bool, threads)
	for _, path := range paths {
		sem <- true
		go func(b string, path string) {
			if CheckIfReachable(b + path) {
				l.Lock()
				availableUrls = append(availableUrls, path)
				l.Unlock()
			}
			<-sem
		}(base, path)
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	return availableUrls
}
func searchPlugins(body *[]byte, cms utility.Cms) []data.CmsPlugin {
	var plugins []data.CmsPlugin
	var pluginNames []string
	pluginRegex := regexp.MustCompile(cms.PluginRegex)
	matches := pluginRegex.FindAllStringSubmatch(string(*body), -1)
	for _, match := range matches {
		if len(match) > 1 {
			pluginNames = append(pluginNames, match[1])
		}
	}
	pluginNames = utility.RemoveDuplicateString(pluginNames)
	for _, name := range pluginNames {
		plugins = append(plugins, data.CmsPlugin{
			Name: name,
		})
	}
	return plugins
}
func searchCms(body *[]byte, cmsConf []utility.Cms) (utility.Cms, string) {
	var foundCms utility.Cms
	foundCms.IsReady = false
	var foundCmsVersion string
	isFound := false
	for _, cms := range cmsConf {
		for _, reg := range cms.SearchRegex {
			r, err := regexp.Compile(reg)
			if err != nil {
				continue
			}
			foundCmsStr := r.FindStringSubmatch(string(*body))
			if len(foundCmsStr) > 0 {
				foundCms = cms
				foundCms.IsReady = true
				isFound = true
				if len(foundCmsStr) > 1 {
					foundVersion := versionRegex.FindStringSubmatch(foundCmsStr[1])
					if len(foundVersion) > 0 {
						foundCmsVersion = foundVersion[0]
					}
				}
				break
			}
		}
		if isFound {
			break
		}
	}
	return foundCms, foundCmsVersion
}
