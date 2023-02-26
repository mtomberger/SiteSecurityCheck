package data

type CmsData struct {
	Name          string
	Version       string
	Plugins       []CmsPlugin
	ReachableUrls []string
	VersionFound  bool
	CmsFound      bool
}
type CmsPlugin struct {
	Name string
}
