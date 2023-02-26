package out

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/utility"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"os"
	"strconv"
)

type Format string

const (
	JsonFormat    Format = "json"
	HumanReadable Format = "human"
)

func CheckFormat(format Format) bool {
	if JsonFormat != format && HumanReadable != format {
		Print(ColorText("Format %s invalid", "red", format))
		return false
	}
	return true
}

func PrintResult(result data.ScanResult, conf utility.ScanConfig, representation Format) {
	if !CheckFormat(representation) {
		return
	}
	if representation == JsonFormat {
		printJson(result)
	} else {
		printHumanReadable(result, conf)
	}
}
func printProperty(s string, p string) {
	fmt.Fprintf(color.Output, "     %-30s%s\n", s, p)
}
func Print(s string, a ...any) {
	fmt.Fprintf(color.Output, s+"\n", a...)
}
func PrintString(s string, a ...any) {
	fmt.Fprintf(color.Output, s, a...)
}
func PrintError(s string, a ...any) {
	fmt.Fprintf(os.Stderr, s+"\n", a...)
}
func PrintHeader(s string) {
	Print(ColorText("  === %s ===", "cyan", s))
}
func PrintScanTitle(url string, representation Format) {
	if representation == JsonFormat {
		return
	}
	Print("\n")
	Print(ColorText("  __ _ _         __                      _ _             ___ _               _    ", "yellow"))
	Print(ColorText(" / _(_) |_ ___  / _\\ ___  ___ _   _ _ __(_) |_ _   _    / __\\ |__   ___  ___| | __", "yellow"))
	Print(ColorText(" \\ \\| | __/ _ \\ \\ \\ / _ \\/ __| | | | '__| | __| | | |  / /  | '_ \\ / _ \\/ __| |/ /", "yellow"))
	Print(ColorText(" _\\ \\ | ||  __/ _\\ \\  __/ (__| |_| | |  | | |_| |_| | / /___| | | |  __/ (__|   < ", "yellow"))
	Print(ColorText(" \\__/_|\\__\\___| \\__/\\___|\\___|\\__,_|_|  |_|\\__|\\__, | \\____/|_| |_|\\___|\\___|_|\\_\\", "yellow"))
	Print(ColorText("                                               |___/                              ", "yellow"))
	Print(ColorText(" ---------------------------------------------------------------------------------", "green"))
	Print(ColorText(" Website Security Check      |      Created by mtomberger      |      License: MIT", "green"))
	Print(ColorText(" ---------------------------------------------------------------------------------", "green"))
	Print(" \n%s%s%s\n", ColorText("Scanning website '", "yellow"), ColorText(url, "green"), ColorText("'...", "yellow"))
}

func printJson(result data.ScanResult) {
	json, err := json.Marshal(result)
	if err != nil {
		Print(ColorText("%s", "red", err))
		return
	}
	Print(string(json))
}
func printHumanReadable(result data.ScanResult, conf utility.ScanConfig) {
	Print("\n")
	printHumanReadableTls(result.Tls)
	printHumanReadableHeaders(result.Headers)
	printHumanReadableServer(result.Server)
	printHumanReadableCms(result.Cms, conf) //TODO implement
	printHumanReadableMisc(result.Miscellaneous)
	printHumanReadablePortScan(result.Ports, conf)
	printHumanReadableVulnerabilities(result.Vulnerabilities)
}
func printHumanReadableHeaders(headerData []data.HeaderData) {
	PrintHeader("Security headers properties")
	for _, h := range headerData {
		c := "red"
		if h.Rating.Rating == 1 {
			c = "yellow"
		} else if h.Rating.Rating > 1 {
			c = "green"
		}
		printProperty(h.HeaderName, ColorText(h.Rating.Description, c))
	}
}
func printHumanReadableTls(tlsData data.TlsData) {
	PrintHeader("TLS properties")
	httpsAvailable := ""
	if tlsData.HttpsAvailable {
		httpsAvailable = ColorText("available", "green")
	} else {
		httpsAvailable = ColorText("not available", "red")
	}
	printProperty("TLS:", httpsAvailable)
	httpsRedirect := ""
	if tlsData.HttpsAvailable && tlsData.RedirectToHttps {
		httpsRedirect = ColorText("available", "green")
	} else {
		httpsRedirect = ColorText("not available", "red")
	}
	printProperty("redirect to TLS:", httpsRedirect)
	if tlsData.HttpsAvailable {
		certValid := ColorText("not valid", "red")
		if tlsData.Valid {
			certValid = ColorText("valid", "green")
		}
		printProperty("TLS certificate:", certValid)
		printProperty("TLS certificate issuer:", tlsData.Issuer)
		printProperty("TLS certificate subject:", tlsData.Subject)
		unavailableV := ""
		availableV := ""
		for i, v := range tlsData.VersionsAvailable {
			c := "green"
			if v.IsOutOfDate {
				c = "red"
			}
			availableV += ColorText(v.Name, c)
			if i < len(tlsData.VersionsAvailable) {
				availableV += ","
			}
		}
		for i, v := range tlsData.VersionsUnavailable {
			c := "green"
			if !v.IsOutOfDate {
				c = "red"
			}
			unavailableV += ColorText(v.Name, c)
			if i < len(tlsData.VersionsUnavailable) {
				unavailableV += ","
			}
		}
		printProperty("TLS versions available:", availableV)
		printProperty("TLS versions not available:", unavailableV)
	}
}
func printHumanReadableServer(serverData data.WebserverData) {
	serverInfo := ColorText("not determinable", "red")
	if serverData.IsServerFound {
		serverVersion := "(Version: " + ColorText("not determinable", "red") + ")"
		if serverData.IsServerVersionFound {
			serverVersion = "(Version: " + ColorText(serverData.ServerVersion, "green") + ")"
		}
		serverInfo = ColorText(serverData.ServerName, "green") + " " + serverVersion
	}
	techInfo := ColorText("not determinable", "red")
	if serverData.IsTechnologyFound {
		techVersion := "(Version: " + ColorText("not determinable", "red") + ")"
		if serverData.IsTechnologyVersionFound {
			techVersion = "(Version: " + ColorText(serverData.TechnologyVersion, "green") + ")"
		}
		techInfo = ColorText(serverData.TechnologyName, "green") + " " + techVersion
	}
	printProperty("Server:", serverInfo)
	printProperty("Technology:", techInfo)
}
func printHumanReadableCms(cmsData data.CmsData, conf utility.ScanConfig) {
	PrintHeader("CMS properties")
	cmsInfo := ColorText("No CMS found", "red")
	if cmsData.CmsFound {
		serverVersion := "(Version: " + ColorText("not determinable", "red") + ")"
		if cmsData.VersionFound {
			serverVersion = "(Version: " + ColorText(cmsData.Version, "green") + ")"
		}
		cmsInfo = ColorText(cmsData.Name, "green") + " " + serverVersion
	}
	printProperty("Content Management System", cmsInfo)
	if cmsData.CmsFound {
		if cmsData.ReachableUrls != nil {
			printProperty(ColorText(" = Suspicious URLs", "cyan"), "")
			for _, u := range cmsData.ReachableUrls {
				printProperty(u, "")
			}
		} else {
			printProperty("Suspicious URLs", ColorText("nothing found", "green"))
		}
		if cmsData.Plugins != nil {
			printProperty(ColorText("= CMS Plugins", "cyan"), "")
			for _, p := range cmsData.Plugins {
				plugin := p.Name
				printProperty(plugin, "")
			}
		} else {
			printProperty("CMS Plugins", ColorText("nothing found", "green"))
		}
	}

}
func printHumanReadablePortScan(ports []data.FoundPort, conf utility.ScanConfig) {
	PrintHeader("Portscan findings")
	if ports == nil {
		printProperty(ColorText("No portscan performed", "red"), "")
	}
	for _, p := range ports {
		c := "red"
		okPorts := []int{80, 8080, 443}
		if utility.Contains(okPorts, p.Port) {
			c = "green"
		}
		printProperty(strconv.Itoa(p.Port)+" "+p.Protocol, ColorText(p.Status, c)+" | "+p.Description)
	}
}
func printHumanReadableMisc(miscData data.MiscellaneousData) {
	PrintHeader("Other findings")
	if len(miscData.ServerHosted) > 0 {
		printProperty("Hosted by: ", miscData.ServerHosted)
	}
	if len(miscData.ServerLocation) > 0 {
		printProperty("Server Location: ", miscData.ServerLocation)
	}
	if len(miscData.ServerIp) > 0 {
		printProperty("Server IP: ", miscData.ServerIp)
	}
	cfStr := "no"
	if miscData.UseCloudflare {
		cfStr = "yes"
	}
	printProperty("UsesCloudflare: ", ColorText(cfStr, "green"))
}
func printHumanReadableVulnerabilities(cveData []data.CveData) {
	if cveData == nil {
		return
	}
	PrintHeader("Vulnerabilities")
	for _, v := range cveData {
		riskStr := v.Risk + " [" + v.RiskName + "]"
		c := "white"
		switch v.RiskName {
		case "low":
			c = "green"
		case "medium":
			c = "yellow"
		case "high":
			c = "red"
		}
		printProperty(v.Id+" - "+ColorText(riskStr, c), v.Name)
	}
}

func ColorText(s string, c string, p ...interface{}) string {
	switch c {
	case "red":
		return color.RedString(s, p...)
	case "green":
		return color.GreenString(s, p...)
	case "yellow":
		return color.YellowString(s, p...)
	case "blue":
		return color.BlueString(s, p...)
	case "magenta":
		return color.MagentaString(s, p...)
	case "cyan":
		return color.CyanString(s, p...)
	case "white":
		return color.WhiteString(s, p...)
	}
	return color.WhiteString(s, p...)
}
