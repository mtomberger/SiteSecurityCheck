package data

import "time"

type MiscellaneousData struct {
	Cookies        []Cookie
	UseCloudflare  bool
	ServerIp       string
	ServerLocation string
	ServerHosted   string
}
type Cookie struct {
	Name    string
	Expires time.Time
}
