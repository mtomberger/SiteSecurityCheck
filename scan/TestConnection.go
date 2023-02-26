package scan

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

func TestConnection(url string, domain string) bool {
	var wg sync.WaitGroup
	isReachable := true
	hasIp := true
	wg.Add(2)
	go func() {
		defer wg.Done()
		isReachable = CheckIfReachable(url)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(3000 * time.Millisecond)
		ipaddrs, err := net.LookupIP(domain)
		if err != nil {
			hasIp = false
			return
		}
		if len(ipaddrs) < 1 {
			hasIp = false
			return
		}
	}()
	wg.Wait()
	return isReachable && hasIp
}
func CheckIfReachable(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return false
	}
	if len(body) == 0 {
		return false
	}
	return true
}
