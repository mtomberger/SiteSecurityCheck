package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/utility"
	"crypto/tls"
	"net/http"
	"sync"
)

type VersionResult struct {
	Version   data.TlsVersion
	Supported bool
	err       error
}

func testTLSVersion(host string, version data.TlsVersion, wg *sync.WaitGroup, resultChan chan VersionResult) {
	defer wg.Done()
	tlsConfig := &tls.Config{
		MinVersion: version.Id,
		MaxVersion: version.Id,
	}
	conn, err := tls.Dial("tcp", host+":443", tlsConfig)
	if err != nil {
		resultChan <- VersionResult{version, false, err}
		return
	}
	defer conn.Close()
	resultChan <- VersionResult{version, true, nil}
}

func tlsVersionCheck(url string, isVerbose bool, conf utility.ScanConfig) data.TlsData {
	versions := []data.TlsVersion{
		{
			Name:        "TLS v1.3",
			IsOutOfDate: false,
			Id:          tls.VersionTLS13,
		},
		{
			Name:        "TLS v1.2",
			IsOutOfDate: false,
			Id:          tls.VersionTLS12,
		},
		{
			Name:        "TLS v1.1",
			IsOutOfDate: true,
			Id:          tls.VersionTLS11,
		},
		{
			Name:        "TLS v1.0",
			IsOutOfDate: true,
			Id:          tls.VersionTLS10,
		},
		{
			Name:        "SSL v3.0",
			IsOutOfDate: true,
			Id:          tls.VersionSSL30,
		},
	}
	var wg sync.WaitGroup
	var tlsData data.TlsData
	threadCh := make(chan struct{}, conf.Threads)
	resultChan := make(chan VersionResult, len(versions))

	for _, version := range versions {
		wg.Add(1)
		threadCh <- struct{}{}
		go func(version data.TlsVersion) {
			defer func() {
				<-threadCh
			}()
			testTLSVersion(url, version, &wg, resultChan)
		}(version)
	}

	wg.Wait()
	close(resultChan)
	certInfoLogged := false
	for result := range resultChan {
		if result.Supported {
			tlsData.VersionsAvailable = append(tlsData.VersionsAvailable, result.Version)
			if !certInfoLogged {
				tlsConfig := &tls.Config{
					MinVersion: result.Version.Id,
					MaxVersion: result.Version.Id,
				}
				conn, err := tls.Dial("tcp", url+":443", tlsConfig)
				if err == nil {
					certInfoLogged = true
					tlsData.Valid = true
					certChain := conn.ConnectionState().PeerCertificates
					cert := certChain[0]
					if isVerbose {
						tlsData.RawCertInfo, err = utility.CertificateText(cert)
					}
					tlsData.NotBefore = cert.NotBefore
					tlsData.NotAfter = cert.NotAfter
					tlsData.Subject = utility.GetSubject(cert)
					tlsData.Issuer = utility.GetIssuer(cert)
					defer conn.Close()
				}

			}
		} else {
			tlsData.VersionsUnavailable = append(tlsData.VersionsUnavailable, result.Version)
		}
	}
	return tlsData
}
func tlsRedirect(domain string) bool {
	resp, err := http.Get("http://" + domain)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return true
	} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location, err := resp.Location()
		return err == nil && location.Scheme == "https"
	}
	return false
}
func tlsAvailable(domain string) bool {
	resp, err := http.Get("https://" + domain)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0
}

func TlsCheck(domain string, isVerbose bool, conf utility.ScanConfig) data.TlsData {
	var wg sync.WaitGroup
	l := sync.Mutex{}
	wg.Add(3)
	tlsData := data.TlsData{}
	go func() {
		defer wg.Done()
		resultTlsData := tlsVersionCheck(domain, isVerbose, conf)
		l.Lock()
		tlsData.RawCertInfo = resultTlsData.RawCertInfo
		tlsData.Subject = resultTlsData.Subject
		tlsData.Issuer = resultTlsData.Issuer
		tlsData.NotAfter = resultTlsData.NotAfter
		tlsData.NotBefore = resultTlsData.NotBefore
		tlsData.Valid = resultTlsData.Valid
		tlsData.VersionsUnavailable = resultTlsData.VersionsUnavailable
		tlsData.VersionsAvailable = resultTlsData.VersionsAvailable
		l.Unlock()
	}()
	go func() {
		defer wg.Done()
		redirToHttps := tlsRedirect(domain)
		l.Lock()
		tlsData.RedirectToHttps = redirToHttps
		l.Unlock()
	}()
	go func() {
		defer wg.Done()
		httpsAvailable := tlsAvailable(domain)
		l.Lock()
		tlsData.HttpsAvailable = httpsAvailable
		l.Unlock()
	}()
	wg.Wait()
	return tlsData
}
