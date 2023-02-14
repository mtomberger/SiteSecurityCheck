package scan

import (
	"SiteSecurityCheck/data"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// KnownPorts struct for Describing ports
type PortScanConfig struct {
	Threads        int `json:"threads"`
	TimeoutSeconds int `json:"timeoutSeconds"`
	PortRangeStart int `json:"portRangeStart"`
	PortRangeStop  int `json:"portRangeStop"`
	Ports          []struct {
		Desc string `json:"desc"`
		Port int    `json:"port"`
	} `json:"ports"`
}

// PortScanner struct for NewPortScanner function
type PortScanner struct {
	host    string
	timeout time.Duration
	threads int
}

func StartPortScan(url string) []data.FoundPort {
	var conf = portsFromConfig()
	var err error

	ipaddrs, err := net.LookupIP(url)
	if err != nil {
		panic(err)
	}
	if len(ipaddrs) < 1 {
		panic("no ip for URL " + url)
	}
	return scanHost(ipaddrs[0].String(), conf)
}

func portsFromConfig() PortScanConfig {
	var ports PortScanConfig
	source, err := os.ReadFile("config/portScanConfig.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(source, &ports)
	if err != nil {
		panic(err)
	}
	return ports
}

func scanHost(host string, conf PortScanConfig) []data.FoundPort {
	ps := newPortScanner(host, time.Duration(conf.TimeoutSeconds)*time.Second, conf.Threads)

	openedPorts := ps.getOpenedPort(conf.PortRangeStart, conf.PortRangeStop)
	var descripedPorts []data.FoundPort
	for i := 0; i < len(openedPorts); i++ {
		var port = openedPorts[i]
		descripedPorts = append(descripedPorts, data.FoundPort{
			Port:     port,
			Protocol: descripePort(port, conf),
			Status:   "open",
		})

	}
	return descripedPorts
}
func descripePort(port int, conf PortScanConfig) string {
	description := "UNKNOWN"
	for _, e := range conf.Ports {
		if e.Port == port {
			description = e.Desc
		}
	}
	return description
}

// NewPortScanner hendler for scanner
func newPortScanner(host string, timeout time.Duration, threads int) *PortScanner {
	return &PortScanner{host, timeout, threads}
}

// IsOpen connect to ports
func (h PortScanner) IsOpen(port int) bool {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", h.hostPort(port))
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), h.timeout)
	if err != nil {
		return false
	}

	defer conn.Close()

	return true
}

// GetOpenedPort work with range of ports
func (h PortScanner) getOpenedPort(portStart int, portEnds int) []int {
	rv := []int{}
	l := sync.Mutex{}
	sem := make(chan bool, h.threads)
	for port := portStart; port <= portEnds; port++ {
		sem <- true
		go func(port int) {
			if h.IsOpen(port) {
				l.Lock()
				rv = append(rv, port)
				l.Unlock()
			}
			<-sem
		}(port)
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	return rv
}

func (h PortScanner) hostPort(port int) string {
	return fmt.Sprintf("%s:%d", h.host, port)
}
