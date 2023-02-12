package data

type CmsData struct {
	Name          string
	Version       string
	Plugins       []CmsPlugin
	ReachableUrls []string
	VersionFound  bool
}
type CmsPlugin struct {
	Name    string
	Version string
}
