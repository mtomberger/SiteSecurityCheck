package utility

import (
	"encoding/json"
	"os"
)

type ScanConfig struct {
	Threads        int      `json:"threads"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	PortRangeTCP   string   `json:"portRangeTCP"`
	PortRangeUDP   string   `json:"portRangeUDP"`
	Cms            []Cms    `json:"cms"`
	Ports          []Port   `json:"ports"`
	CloudflareIps  []string `json:"cloudflareIps"`
}
type Cms struct {
	Name        string   `json:"name"`
	SearchRegex []string `json:"searchRegex"`
	Urls        []string `json:"urls"`
	PluginRegex string   `json:"pluginRegex"`
	IsReady     bool     `json:"-"`
}
type Port struct {
	Desc     string `json:"desc"`
	Port     int    `json:"port"`
	LongDesc string `json:"longDesc,omitempty"`
	Protocol string `json:"protocol"`
}

func GetConfiguration(path string) ScanConfig {
	if len(path) == 0 {
		path = "config/scanConfig.json"
	}
	var ports ScanConfig
	source, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(source, &ports)
	if err != nil {
		panic(err)
	}
	return ports
}
