package main

import (
	"fmt"
	"github.com/fatih/color"
	"os"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("usage:" + args[0] + " <url> <args..>")
	}
	websiteURL := args[1]
	print("\n%s%s%s", colorText("Scanning website '", "yellow"), colorText(websiteURL, "green"), colorText("'...", "yellow"))
	print(colorText("====================================> finished", "green"))
	printHeader("TLS properties")
	print("    versions available: %s, %s, %s", colorText("TLS 1.1", "red"), colorText("TLS 1.2", "green"), colorText("TLS 1.3", "green"))
	print("    versions not available: %s, %s, %s, %s", colorText("TLS 1.3", "red"), colorText("SSL 2.0", "green"), colorText("SSL 3.0", "green"), colorText("TLS 1.0", "green"))
	print("    TLS certificate for %s", colorText("*.alfright.eu", "green"))
	print("    cert issuer: R3 Let's Encrypt")
	print("    cert valid: %s %s", colorText("yes", "green"), "(not after: 2023-03-10 09:36:13)")
	print("    cert SHA-256: %s", "6F2417EE464FE581486574FF07AC688949DBBB27DA095D8926E90D53EA282F73")
	print("    cert SHA-1: %s", "3933E713BD11747A498E9539E82643EB3FA8CFC5")
	printHeader("webserver properties")
	print("    version: Apache %s", colorText("2.4.54", "green"))
	print("    PHP is supported and/or running (Version: %s)", colorText("not found", "red"))
	printHeader("CMS properties")
	print("    CMS found: %s", colorText("WordPress (Version: 6.1.1)", "green"))
	print("      discovered wordpress plugins: %s", "elementor, borlabs-cookie, wordpress-seo")
	print("      possibly unwanted accessable URLs:")
	print("        /wp-cron.php")
	print("        /readme.html")
	printHeader("security headers properties")
	print("    uses Cloudflare: %s", colorText("no", "red"))
	printHeader("other findings")
	print("    uses Cloudflare: %s", colorText("no", "red"))
	print("    server IP: %s", "81.19.159.61")
	print("    server location: %s", "Linz, Austria (48°18'23\"N   14°17'10\"E)")
	print("    hosted by: %s", "World4You Internet Services GmbH")
	print("    set cookies")
	print("      PHPSESSID (%s, %s)", colorText("httponly", "green"), colorText("secure", "green"))

	print(colorText("\nSearch for other services on common ports...", "yellow"))
	print(colorText("====================================> finished", "green"))
	printHeader("open ports found:")
	print("    80 (TCP)  open  http")
	print(colorText("no additional services found", "red"))
	printHeader("listing applicable CVE identifiers:")
	print("CVE-2022-3590 %s %s(%s)", colorText("medium (5.6)", "yellow"), "WordPress Pingback server-side request forgery", "https://vuldb.com/?id.215810")

}
func print(s string, a ...any) {
	fmt.Fprintf(color.Output, s+"\n", a...)
}
func printHeader(s string) {
	print(colorText("  === %s ===", "cyan", s))
}
func colorText(s string, c string, p ...interface{}) string {
	switch c {
	case "red":
		return color.RedString(s, p...)
	case "green":
		return color.GreenString(s, p...)
	case "yellow":
		return color.YellowString(s, p...)
	case "blue":
		return color.BlueString(s, p...)
	case "magenta":
		return color.MagentaString(s, p...)
	case "cyan":
		return color.CyanString(s, p...)
	case "white":
		return color.WhiteString(s, p...)
	}
	return color.WhiteString(s, p...)
}
