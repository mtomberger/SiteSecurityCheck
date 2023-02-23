package utility

import (
	"encoding/json"
	"os"
)

type ScanConfig struct {
	Threads        int `json:"threads"`
	TimeoutSeconds int `json:"timeoutSeconds"`
	PortRangeStart int `json:"portRangeStart"`
	PortRangeStop  int `json:"portRangeStop"`
	Ports          []struct {
		Desc string `json:"desc"`
		Port int    `json:"port"`
	} `json:"ports"`
	CloudflareIps []string `json:"cloudflareIps"`
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
