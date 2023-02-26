package scan

import (
	"SiteSecurityCheck/data"
	"SiteSecurityCheck/out"
	"net/http"
	"strings"
)

type headerInfo struct {
	Name            string
	CalculateRating func(headerInfo, string) data.HeaderRating
}

const notSetText = "Header was not set"
const docLinkBase = "https://developer.mozilla.org/Web/HTTP/Headers/"

var headerInfos = []headerInfo{
	{
		Name: "X-Frame-Options",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			if strings.Contains(strings.ToLower(value), "deny") {
				return data.HeaderRating{
					Rating:      2,
					Description: "The page cannot be displayed in a frame, regardless of the site attempting to do so.",
				}
			} else if strings.Contains(strings.ToLower(value), "sameorigin") {
				return data.HeaderRating{
					Rating:      2,
					Description: "The page can only be displayed if all ancestor frames are same origin to the page itself.",
				}
			} else if strings.Contains(strings.ToLower(value), "allow-from") {
				return data.HeaderRating{
					Rating:      0,
					Description: "Obsolete Directive 'allow-from'",
				}
			}
			return data.HeaderRating{
				Rating:      0,
				Description: "Invalid Content '" + shortenHeaderValue(value, 15) + "'",
			}
		},
	},
	{
		Name: "X-Content-Type-Options",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			if strings.Contains(strings.ToLower(value), "nosniff") {
				return data.HeaderRating{
					Rating:      2,
					Description: "This header prevents MIME sniffing",
				}
			}
			return data.HeaderRating{
				Rating:      0,
				Description: "Invalid Content '" + shortenHeaderValue(value, 15) + "'",
			}
		},
	},
	{
		Name: "Content-Security-Policy",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			return data.HeaderRating{
				Rating:      2,
				Description: "Content-Security-Policy in place: " + shortenHeaderValue(value, 15),
			}
		},
	},
	{
		Name: "Referrer-Policy",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			lowerVal := strings.ToLower(value)
			switch {
			case strings.Contains(lowerVal, "unsafe-url"):
				return data.HeaderRating{
					Rating:      0,
					Description: "Leaks data to insecure third parties",
				}
			case strings.Contains(lowerVal, "strict-origin-when-cross-origin"):
				return data.HeaderRating{
					Rating:      0,
					Description: "Leaks data to secure third parties",
				}
			case strings.Contains(lowerVal, "same-origin"):
				return data.HeaderRating{
					Rating:      2,
					Description: "Does not leak data",
				}
			case strings.Contains(lowerVal, "origin-when-cross-origin"):
				return data.HeaderRating{
					Rating:      1,
					Description: "Leaks the origin of the request to third parties",
				}
			case strings.Contains(lowerVal, "no-referrer-when-downgrade"):
				return data.HeaderRating{
					Rating:      0,
					Description: "Leaks data to third parties if the security level stays the same",
				}
			case strings.Contains(lowerVal, "no-referrer"):
				return data.HeaderRating{
					Rating:      2,
					Description: "Referer disabled. Does not leak data",
				}
			case strings.Contains(lowerVal, "strict-origin"):
				return data.HeaderRating{
					Rating:      1,
					Description: "Leaks the origin of the request to third parties if the security level stays the same",
				}
			case strings.Contains(lowerVal, "origin"):
				return data.HeaderRating{
					Rating:      1,
					Description: "Leaks the origin of the request to third parties",
				}
			}
			return data.HeaderRating{
				Rating:      0,
				Description: "Invalid Content '" + shortenHeaderValue(value, 15) + "'",
			}
		},
	},
	{
		Name: "Permissions-Policy",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			return data.HeaderRating{
				Rating:      2,
				Description: "Permissions-Policy in place: " + shortenHeaderValue(value, 15),
			}
		},
	},
	{
		Name: "Strict-Transport-Security",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			lowerVal := strings.ToLower(value)
			r := data.HeaderRating{
				Rating:      0,
				Description: "Invalid Content '" + shortenHeaderValue(value, 15) + "'",
			}
			if strings.Contains(lowerVal, "max-age=") {
				r.Rating++
				r.Description = "HSTS enforced"
				if strings.Contains(lowerVal, "includeSubDomains ") {
					r.Description += ", subdomains are included"
					r.Rating++
				} else {
					r.Description += ", subdomains are not included"
				}
			}
			return r
		},
	},
	{
		Name: "Set-Cookie",
		CalculateRating: func(info headerInfo, value string) data.HeaderRating {
			return data.HeaderRating{
				Rating:      0,
				Description: "Tries to set cookies",
			}
		},
	},
}

func shortenHeaderValue(value string, size int) string {
	if len(value) <= size {
		return value
	}
	return value[0:size] + "..."
}
func analyzeHeader(headers http.Header, info headerInfo, isVerbose bool) data.HeaderData {
	value := headers.Get(info.Name)
	headerData := data.HeaderData{
		HeaderName: info.Name,
	}
	if isVerbose {
		headerData.DocLink = docLinkBase + info.Name
	}
	if value == "" {
		headerData.IsSet = false
		headerData.Rating = data.HeaderRating{
			Rating:      0,
			Description: notSetText,
		}
	} else {
		headerData.IsSet = true
		headerData.Rating = info.CalculateRating(info, value)
	}
	return headerData
}

func AnalyzeHeaders(url string, isVerbose bool) []data.HeaderData {
	resp, err := http.Get(url)
	if err != nil {
		out.PrintError("AnalyzeHeaders: url not reachable %s", err.Error())
		return nil
	}
	defer resp.Body.Close()

	var headers []data.HeaderData
	for _, info := range headerInfos {
		headers = append(headers, analyzeHeader(resp.Header, info, isVerbose))
	}
	return headers
}
