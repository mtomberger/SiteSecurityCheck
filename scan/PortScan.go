package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/utility"
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
	CloudflareIps []string `json:"cloudflareIps"`
}

// PortScanner struct for NewPortScanner function
type PortScanner struct {
	host    string
	timeout time.Duration
	threads int
}

func getIp(url string) string {
	ipaddrs, err := net.LookupIP(url)
	if err != nil {
		panic(err)
	}
	if len(ipaddrs) < 1 {
		panic("no ip for URL " + url)
	}
	return ipaddrs[0].String()
}
func IsCloudflare(url string) bool {
	var conf = portsFromConfig()
	ipaddr := getIp(url)
	for _, c := range conf.CloudflareIps {
		if c == "" {
			continue
		}

		hosts, err := hosts(c)
		if err != nil {
			continue
		}

		for _, host := range hosts {
			if host == ipaddr {
				return true
			}
		}
	}
	return false
}
func hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil
	default:
		return ips[1 : len(ips)-1], nil
	}
}
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func StartPortScan(url string, conf utility.ScanConfig) []data.FoundPort {
	return scanHost(getIp(url), conf)
}

func portsFromConfig() PortScanConfig {
	var ports PortScanConfig
	source, err := os.ReadFile("config/scanConfig.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(source, &ports)
	if err != nil {
		panic(err)
	}
	return ports
}

func scanHost(host string, conf utility.ScanConfig) []data.FoundPort {
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
func descripePort(port int, conf utility.ScanConfig) string {
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
