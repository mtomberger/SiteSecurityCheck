package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/utility"
	"crypto/tls"
	"encoding/json"
	"os"
	"sync"
)

type TlsScanConfig struct {
	Threads int `json:"threads"`
}

func getTlsConfig() TlsScanConfig {
	var ports TlsScanConfig
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

func TlsCheck(url string) data.TlsData {
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
	conf := getTlsConfig()

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
					tlsData.RawCertInfo, err = utility.CertificateText(cert)
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
