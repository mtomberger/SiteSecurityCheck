package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"SiteSecurityCheck/utility"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortScanner struct for NewPortScanner function
type PortScanner struct {
	host    string
	timeout time.Duration
	threads int
}
type Port struct {
	port     int
	protocol string
}

func getIp(url string) string {
	ipaddrs, err := net.LookupIP(url)
	if err != nil {
		return ""
	}
	if len(ipaddrs) < 1 {
		panic("no ip for URL " + url)
	}
	return ipaddrs[0].String()
}
func IsCloudflare(url string, conf utility.ScanConfig) bool {
	ipaddr := getIp(url)
	if len(ipaddr) == 0 {
		return false
	}
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
func getPorts(conf utility.ScanConfig) []Port {
	var ports []Port
	tcp := getPortRange(conf.PortRangeTCP)
	udp := getPortRange(conf.PortRangeUDP)
	for _, t := range tcp {
		ports = append(ports, Port{
			port:     t,
			protocol: "TCP",
		})
	}
	for _, t := range udp {
		ports = append(ports, Port{
			port:     t,
			protocol: "UDP",
		})
	}
	return ports

}
func getPortRange(portRangeStr string) []int {
	var portRange []int
	if len(portRangeStr) == 0 {
		return portRange
	}
	ranges := strings.Split(portRangeStr, ",")
	var invalidRanges []string
	for _, r := range ranges {
		borders := strings.Split(r, "-")
		if len(borders) == 2 {
			pS, errS := strconv.Atoi(strings.TrimSpace(borders[0]))
			pE, errP := strconv.Atoi(strings.TrimSpace(borders[1]))
			if errS == nil && errP == nil && pS <= pE {
				for i := pS; i < pE; i++ {
					portRange = append(portRange, i)
				}
			} else {
				invalidRanges = append(invalidRanges, r)
			}
		} else if len(borders) == 1 {
			p, err := strconv.Atoi(strings.TrimSpace(borders[0]))
			if err == nil {
				portRange = append(portRange, p)
			} else {
				invalidRanges = append(invalidRanges, r)
			}
		}
	}
	if len(invalidRanges) > 0 {
		m := ""
		if len(invalidRanges) > 1 {
			m = "s"
		}
		out.PrintError("%d invalid range%s in portRange config: '%s'", len(invalidRanges), m, strings.Join(invalidRanges, "','"))
	}
	return utility.RemoveDuplicateInt(portRange)
}

func scanHost(host string, conf utility.ScanConfig) []data.FoundPort {
	var describedPorts []data.FoundPort
	if len(host) == 0 {
		return nil
	}
	ps := newPortScanner(host, time.Duration(conf.TimeoutSeconds)*time.Second, conf.Threads)
	openedPorts := ps.getOpenedPort(getPorts(conf))

	for i := 0; i < len(openedPorts); i++ {
		var port = openedPorts[i]
		var shDesc, longDesc = descripePort(port, conf)
		describedPorts = append(describedPorts, data.FoundPort{
			Port:        port.port,
			Protocol:    shDesc,
			Description: longDesc,
			Status:      "open",
		})

	}
	return describedPorts
}
func descripePort(port Port, conf utility.ScanConfig) (string, string) {
	short := "UNKNOWN"
	longD := ""
	for _, e := range conf.Ports {
		if e.Port == port.port {
			short = e.Desc + " (" + port.protocol + ")"
			longD = e.LongDesc
		}
	}
	return short, longD
}

// NewPortScanner handler for scanner
func newPortScanner(host string, timeout time.Duration, threads int) *PortScanner {
	return &PortScanner{host, timeout, threads}
}

// IsOpen connect to ports
func (h PortScanner) IsOpen(port Port) bool {
	if port.protocol == "TCP" {
		tcpAddr, err := net.ResolveTCPAddr("tcp4", h.hostPort(port.port))
		if err != nil {
			return false
		}
		conn, err := net.DialTimeout("tcp", tcpAddr.String(), h.timeout)
		if err != nil {
			return false
		}
		defer conn.Close()
	} else if port.protocol == "UDP" {
		udpAddr, err := net.ResolveUDPAddr("udp4", h.hostPort(port.port))
		if err != nil {
			return false
		}
		conn, err := net.DialTimeout("udp", udpAddr.String(), h.timeout)
		if err != nil {
			return false
		}
		defer conn.Close()
	}

	return true
}

// GetOpenedPort work with range of ports
func (h PortScanner) getOpenedPort(portRange []Port) []Port {
	rv := []Port{}
	l := sync.Mutex{}
	sem := make(chan bool, h.threads)
	for _, port := range portRange {
		sem <- true
		go func(port Port) {
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
