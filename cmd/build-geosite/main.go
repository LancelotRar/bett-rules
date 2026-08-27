package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/geo/convert"
	"github.com/metacubex/geo/encoding/v2raygeo"
	"google.golang.org/protobuf/proto"
)

type domainNode struct {
	children map[string]*domainNode
	isLeaf   bool
}

func newDomainNode() *domainNode {
	return &domainNode{children: make(map[string]*domainNode)}
}

func (n *domainNode) insert(domain string) bool {
	parts := strings.Split(strings.ToLower(domain), ".")
	curr := n
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if curr.isLeaf {
			return false
		}
		if curr.children[part] == nil {
			curr.children[part] = newDomainNode()
		}
		curr = curr.children[part]
	}
	if len(curr.children) > 0 {
		curr.children = make(map[string]*domainNode)
	}
	curr.isLeaf = true
	return true
}

func fetchURL(url string) ([]byte, error) {
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func fetchLines(url string) ([]string, error) {
	b, err := fetchURL(url)
	if err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func main() {
	outputDir := flag.String("out", "./publish", "Output directory for compiled assets")
	flag.Parse()

	startTime := time.Now()
	fmt.Println("🚀 Starting Native GeoSite Build Engine (Full & Lite)...")

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Printf("❌ Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "geosite-build-*")
	if err != nil {
		fmt.Println("Error creating temp dir:", err)
		return
	}
	defer os.RemoveAll(tempDir)

	dataDir := filepath.Join(tempDir, "data")
	_ = os.MkdirAll(dataDir, 0755)

	fmt.Println("⏳ Fetching v2fly/domain-list-community master archive...")
	tarGzData, err := fetchURL("https://github.com/v2fly/domain-list-community/archive/refs/heads/master.tar.gz")
	if err != nil {
		fmt.Println("❌ Failed to download community archive:", err)
		return
	}

	gzReader, _ := gzip.NewReader(strings.NewReader(string(tarGzData)))
	tarReader := tar.NewReader(gzReader)

	extractedCount := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF || err != nil {
			break
		}

		if strings.Contains(header.Name, "/data/") && !header.FileInfo().IsDir() {
			fileName := filepath.Base(header.Name)
			destPath := filepath.Join(dataDir, fileName)
			outFile, err := os.Create(destPath)
			if err == nil {
				_, _ = io.Copy(outFile, tarReader)
				outFile.Close()
				extractedCount++
			}
		}
	}
	fmt.Printf("✅ Extracted %d community rule files\n", extractedCount)

	fmt.Println("⏳ Fetching dnsmasq-china-list (CN direct)...")
	cnRaw, err := fetchURL("https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf")
	var cnClean []string
	if err == nil {
		tree := newDomainNode()
		scanner := bufio.NewScanner(strings.NewReader(string(cnRaw)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "server=/") {
				parts := strings.Split(line, "/")
				if len(parts) >= 2 {
					dom := parts[1]
					if tree.insert(dom) {
						cnClean = append(cnClean, dom)
					}
				}
			}
		}
		_ = os.WriteFile(filepath.Join(dataDir, "cn"), []byte(strings.Join(cnClean, "\n")), 0644)
		fmt.Printf("✅ Injected pure CN list: %d domains\n", len(cnClean))
	}

	gcnRaw, _ := fetchURL("https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf")
	if len(gcnRaw) > 0 {
		var gcn []string
		scanner := bufio.NewScanner(strings.NewReader(string(gcnRaw)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "server=/") {
				parts := strings.Split(line, "/")
				if len(parts) >= 2 {
					gcn = append(gcn, "full:"+parts[1])
				}
			}
		}
		_ = os.WriteFile(filepath.Join(dataDir, "google-cn"), []byte(strings.Join(gcn, "\n")), 0644)
	}

	acnRaw, _ := fetchURL("https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf")
	if len(acnRaw) > 0 {
		var acn []string
		scanner := bufio.NewScanner(strings.NewReader(string(acnRaw)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "server=/") {
				parts := strings.Split(line, "/")
				if len(parts) >= 2 {
					acn = append(acn, "full:"+parts[1])
				}
			}
		}
		_ = os.WriteFile(filepath.Join(dataDir, "apple-cn"), []byte(strings.Join(acn, "\n")), 0644)
	}

	rejectWL := make(map[string]bool)
	if wlRaw, err := os.ReadFile("resouces/reject-need-to-remove.txt"); err == nil {
		for _, line := range strings.Split(string(wlRaw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				rejectWL[strings.ToLower(line)] = true
			}
		}
	}
	var customRejects []string
	if rejRaw, err := os.ReadFile("resouces/reject.txt"); err == nil {
		tree := newDomainNode()
		for _, line := range strings.Split(string(rejRaw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !rejectWL[strings.ToLower(line)] {
				if tree.insert(line) {
					customRejects = append(customRejects, line)
				}
			}
		}
		if len(customRejects) > 0 {
			adsPath := filepath.Join(dataDir, "category-ads")
			f, _ := os.OpenFile(adsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			_, _ = f.WriteString("\n" + strings.Join(customRejects, "\n") + "\n")
			f.Close()
			fmt.Printf("✅ Injected %d custom reject rules into category-ads\n", len(customRejects))
		}
	}

	proxyWL := make(map[string]bool)
	if wlRaw, err := os.ReadFile("resouces/proxy-need-to-remove.txt"); err == nil {
		for _, line := range strings.Split(string(wlRaw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				proxyWL[strings.ToLower(line)] = true
			}
		}
	}
	var customProxies []string
	if prxRaw, err := os.ReadFile("resouces/proxy.txt"); err == nil {
		tree := newDomainNode()
		for _, line := range strings.Split(string(prxRaw), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !proxyWL[strings.ToLower(line)] {
				if tree.insert(line) {
					customProxies = append(customProxies, line)
				}
			}
		}
		if len(customProxies) > 0 {
			prxPath := filepath.Join(dataDir, "geolocation-!cn")
			f, _ := os.OpenFile(prxPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			_, _ = f.WriteString("\n" + strings.Join(customProxies, "\n") + "\n")
			f.Close()
			fmt.Printf("✅ Injected %d custom proxy rules into geolocation-!cn\n", len(customProxies))
		}
	}

	fmt.Println("🧩 Parsing and recursively resolving Full GeoSite entries...")
	files, _ := os.ReadDir(dataDir)

	type rawEntry struct {
		line    string
		isInc   bool
		incName string
		incAttr string
	}

	rawMap := make(map[string][]rawEntry)

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		tagName := strings.ToLower(file.Name())
		filePath := filepath.Join(dataDir, file.Name())

		f, err := os.Open(filePath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "include:") {
				incPart := strings.TrimPrefix(line, "include:")
				incParts := strings.Fields(incPart)
				incName := strings.ToLower(incParts[0])
				incAttr := ""
				if len(incParts) > 1 {
					incAttr = incParts[1]
				}
				rawMap[tagName] = append(rawMap[tagName], rawEntry{
					isInc:   true,
					incName: incName,
					incAttr: incAttr,
				})
			} else {
				rawMap[tagName] = append(rawMap[tagName], rawEntry{
					line: line,
				})
			}
		}
		f.Close()
	}

	resolveTag := func(tag string) []string {
		var result []string
		visited := make(map[string]bool)

		var dfs func(currTag string, filterAttr string)
		dfs = func(currTag string, filterAttr string) {
			if visited[currTag] {
				return
			}
			visited[currTag] = true

			for _, item := range rawMap[currTag] {
				if item.isInc {
					dfs(item.incName, item.incAttr)
				} else {
					line := item.line
					if filterAttr != "" {
						if !strings.Contains(line, filterAttr) {
							continue
						}
					}
					result = append(result, line)
				}
			}
		}
		dfs(tag, "")
		return result
	}

	var siteListFull []*v2raygeo.GeoSite

	for tag := range rawMap {
		allLines := resolveTag(tag)
		var domains []*v2raygeo.Domain
		seen := make(map[string]bool)

		for _, line := range allLines {
			dType := v2raygeo.Domain_Domain
			val := line

			if strings.HasPrefix(line, "full:") {
				dType = v2raygeo.Domain_Full
				val = strings.TrimPrefix(line, "full:")
			} else if strings.HasPrefix(line, "regexp:") {
				dType = v2raygeo.Domain_Regex
				val = strings.TrimPrefix(line, "regexp:")
			} else if strings.HasPrefix(line, "keyword:") {
				dType = v2raygeo.Domain_Plain
				val = strings.TrimPrefix(line, "keyword:")
			} else if strings.HasPrefix(line, "domain:") {
				dType = v2raygeo.Domain_Domain
				val = strings.TrimPrefix(line, "domain:")
			}

			if idx := strings.Index(val, "@"); idx != -1 {
				val = strings.TrimSpace(val[:idx])
			}
			if idx := strings.Index(val, ":@"); idx != -1 {
				val = strings.TrimSpace(val[:idx])
			}

			key := fmt.Sprintf("%d:%s", dType, val)
			if val != "" && !seen[key] {
				seen[key] = true
				domains = append(domains, &v2raygeo.Domain{
					Type:  dType,
					Value: val,
				})
			}
		}

		if len(domains) > 0 {
			siteListFull = append(siteListFull, &v2raygeo.GeoSite{
				CountryCode: strings.ToUpper(tag),
				Domain:      domains,
			})
		}
	}

	protoDataFull, _ := proto.Marshal(&v2raygeo.GeoSiteList{Entry: siteListFull})
	datPath := filepath.Join(*outputDir, "geosite.dat")
	_ = os.WriteFile(datPath, protoDataFull, 0644)

	dbPath := filepath.Join(*outputDir, "geosite.db")
	if dbFile, err := os.Create(dbPath); err == nil {
		_ = convert.V2RaySiteToSing(siteListFull, dbFile)
		dbFile.Close()
	}

	fmt.Println("🧩 Compiling Lite GeoSite entries...")
	var siteListLite []*v2raygeo.GeoSite

	var cnDomainsLite []*v2raygeo.Domain
	for _, dom := range cnClean {
		cnDomainsLite = append(cnDomainsLite, &v2raygeo.Domain{
			Type:  v2raygeo.Domain_Domain,
			Value: dom,
		})
	}
	siteListLite = append(siteListLite, &v2raygeo.GeoSite{
		CountryCode: "CN",
		Domain:      cnDomainsLite,
	})

	liteSources := map[string]string{
		"google":    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml",
		"openai":    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml",
		"telegram":  "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.yaml",
		"twitter":   "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Twitter/Twitter.yaml",
		"netflix":   "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml",
		"github":    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml",
		"microsoft": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Microsoft/Microsoft.yaml",
		"apple":     "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Apple/Apple_Classical.yaml",
		"spotify":   "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml",
		"bilibili":  "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/BiliBili/BiliBili.yaml",
		"tiktok":    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml",
		"youtube":   "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml",
	}

	for tag, url := range liteSources {
		lines, err := fetchLines(url)
		if err != nil {
			continue
		}
		var domains []*v2raygeo.Domain
		t := newDomainNode()
		for _, l := range lines {
			l = strings.TrimPrefix(l, "payload:")
			l = strings.TrimSpace(l)
			l = strings.TrimPrefix(l, "- '")
			l = strings.TrimPrefix(l, "- \"")
			l = strings.TrimPrefix(l, "- ")
			l = strings.TrimSuffix(l, "'")
			l = strings.TrimSuffix(l, "\"")
			l = strings.TrimPrefix(l, "+.")
			l = strings.TrimPrefix(l, "DOMAIN-SUFFIX,")
			l = strings.TrimPrefix(l, "DOMAIN,")
			l = strings.TrimPrefix(l, "full:")
			if l != "" && !strings.Contains(l, "IP-CIDR") {
				if t.insert(l) {
					domains = append(domains, &v2raygeo.Domain{
						Type:  v2raygeo.Domain_Domain,
						Value: l,
					})
				}
			}
		}
		siteListLite = append(siteListLite, &v2raygeo.GeoSite{
			CountryCode: strings.ToUpper(tag),
			Domain:      domains,
		})
	}

	if len(customRejects) > 0 {
		var adsDomainsLite []*v2raygeo.Domain
		for _, d := range customRejects {
			adsDomainsLite = append(adsDomainsLite, &v2raygeo.Domain{
				Type:  v2raygeo.Domain_Domain,
				Value: d,
			})
		}
		siteListLite = append(siteListLite, &v2raygeo.GeoSite{
			CountryCode: "CATEGORY-ADS",
			Domain:      adsDomainsLite,
		})
	}

	protoDataLite, _ := proto.Marshal(&v2raygeo.GeoSiteList{Entry: siteListLite})
	datLitePath := filepath.Join(*outputDir, "geosite-lite.dat")
	_ = os.WriteFile(datLitePath, protoDataLite, 0644)

	dbLitePath := filepath.Join(*outputDir, "geosite-lite.db")
	if dbLiteFile, err := os.Create(dbLitePath); err == nil {
		_ = convert.V2RaySiteToSing(siteListLite, dbLiteFile)
		dbLiteFile.Close()
	}

	fmt.Printf("🎉 All GeoSite assets successfully built in %v!\n", time.Since(startTime))
}
