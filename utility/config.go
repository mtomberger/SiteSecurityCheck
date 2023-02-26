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
	IsReady        bool     `json:"-"`
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
	var conf ScanConfig
	conf.IsReady = false
	source, err := os.ReadFile(path)
	if err != nil {
		return conf
	}
	err = json.Unmarshal(source, &conf)
	if err != nil {
		return conf
	}
	conf.IsReady = true
	return conf
}
