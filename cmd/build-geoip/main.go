package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/metacubex/geo/encoding/v2raygeo"
	"go4.org/netipx"
	"google.golang.org/protobuf/proto"
)

var privateCIDRs = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"2001:db8::/32",
	"100::/64",
}

var liteCountries = map[string]bool{
	"CN": true,
}

var fallbackCloudflareCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var preciseASNs = map[string]map[string]bool{
	"telegram":  {"AS44907": true, "AS62041": true, "AS62014": true, "AS59930": true, "AS211157": true},
	"openai":    {"AS398324": true, "AS401518": true},
	"twitter":   {"AS13414": true, "AS35995": true, "AS63179": true, "AS18747": true, "AS62904": true, "AS152868": true, "AS26662": true, "AS49532": true},
	"steam":     {"AS32590": true, "AS214256": true, "AS136784": true, "AS268379": true, "AS60086": true},
	"spotify":   {"AS19679": true},
	"netflix":   {"AS2906": true, "AS40027": true, "AS55095": true},
	"facebook":  {"AS32934": true, "AS63293": true, "AS54115": true},
	"apple":     {"AS714": true, "AS6185": true, "AS139901": true, "AS35026": true, "AS31128": true, "AS210176": true, "AS138575": true, "AS136716": true, "AS400506": true, "AS40058": true},
	"tiktok":    {"AS138699": true, "AS396986": true, "AS11983": true},
	"bilibili":  {"AS140222": true, "AS140633": true},
	"fastly":    {"AS54113": true},
	"akamai":    {"AS20940": true, "AS36183": true, "AS32787": true, "AS16625": true, "AS63949": true, "AS35994": true, "AS24319": true, "AS34164": true, "AS12222": true},
	"microsoft": {"AS8075": true, "AS8069": true, "AS3598": true, "AS8068": true, "AS8070": true, "AS35106": true, "AS12076": true},
	"google":    {"AS15169": true, "AS396982": true, "AS394089": true, "AS45566": true, "AS36384": true, "AS36411": true, "AS36383": true, "AS36040": true, "AS19527": true, "AS43515": true, "AS36492": true},
}

var requireNonCN = map[string]bool{
	"apple":      true,
	"microsoft":  true,
	"akamai":     true,
	"fastly":     true,
	"tiktok":     true,
	"bilibili":   true,
	"cloudflare": true,
	"cloudfront": true,
}

func main() {
	inputFile := flag.String("input", "ipinfo_lite.csv.gz", "Path to ipinfo_lite.csv.gz")
	outputDir := flag.String("out", "./publish", "Output directory for compiled assets")
	flag.Parse()

	startTime := time.Now()
	fmt.Printf("🚀 Starting GeoIP build from: %s\n", *inputFile)

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Printf("❌ Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	cfPrefixes := fetchCloudflareIPs()
	cfFrontPrefixes := fetchCloudFrontIPs()

	var cfBuilder netipx.IPSetBuilder
	for _, p := range cfPrefixes {
		cfBuilder.AddPrefix(p)
	}
	cfSet, _ := cfBuilder.IPSet()

	var cfFrontBuilder netipx.IPSetBuilder
	for _, p := range cfFrontPrefixes {
		cfFrontBuilder.AddPrefix(p)
	}
	cfFrontSet, _ := cfFrontBuilder.IPSet()

	file, err := os.Open(*inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to open input file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	gz, err := gzip.NewReader(bufio.NewReaderSize(file, 4*1024*1024))
	if err != nil {
		fmt.Printf("❌ Failed to init gzip reader: %v\n", err)
		os.Exit(1)
	}
	defer gz.Close()

	csvReader := csv.NewReader(gz)
	csvReader.ReuseRecord = true

	if _, err := csvReader.Read(); err != nil {
		fmt.Printf("❌ Failed to read CSV header: %v\n", err)
		os.Exit(1)
	}

	countryFull := make(map[string][]netip.Prefix, 256)
	countryLite := make(map[string][]netip.Prefix, 2)
	serviceFull := make(map[string][]netip.Prefix, 20)
	serviceLite := make(map[string][]netip.Prefix, 20)
	asnMap := make(map[uint32][]netip.Prefix, 60000)
	asnMapLite := make(map[uint32][]netip.Prefix, 1000)
	asnNameMap := make(map[uint32]string, 60000)

	var privatePrefixes []netip.Prefix
	for _, s := range privateCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			privatePrefixes = append(privatePrefixes, p)
		}
	}
	serviceFull["private"] = privatePrefixes
	serviceLite["private"] = privatePrefixes

	serviceFull["cloudflare"] = cfPrefixes
	serviceLite["cloudflare"] = cfPrefixes

	if len(cfFrontPrefixes) > 0 {
		serviceFull["cloudfront"] = cfFrontPrefixes
		serviceLite["cloudfront"] = cfFrontPrefixes
	}

	fmt.Println("⏳ Parsing CSV records...")
	rowCount := 0

	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 8 {
			continue
		}

		rowCount++
		networkStr := rec[0]
		cc := strings.ToUpper(strings.TrimSpace(rec[2]))
		asnStr := strings.ToUpper(strings.TrimSpace(rec[5]))
		asName := rec[6]

		prefix, err := netip.ParsePrefix(networkStr)
		if err != nil {
			continue
		}

		addr := prefix.Addr()
		if addr.Is4() && prefix.Bits() > 24 {
			if norm, err := addr.Prefix(24); err == nil {
				prefix = norm
			}
		} else if addr.Is6() && prefix.Bits() > 44 {
			if norm, err := addr.Prefix(44); err == nil {
				prefix = norm
			}
		}

		if cc != "" {
			countryFull[cc] = append(countryFull[cc], prefix)
			if liteCountries[cc] {
				countryLite[cc] = append(countryLite[cc], prefix)
			}
		}

		for tag, asns := range preciseASNs {
			if asns[asnStr] {
				if requireNonCN[tag] && cc == "CN" {
					continue
				}
				serviceFull[tag] = append(serviceFull[tag], prefix)
				serviceLite[tag] = append(serviceLite[tag], prefix)
			}
		}

		if strings.HasPrefix(asnStr, "AS") {
			if num, err := strconv.ParseUint(asnStr[2:], 10, 32); err == nil && num > 0 {
				asnNum := uint32(num)
				asnMap[asnNum] = append(asnMap[asnNum], prefix)
				if _, ok := asnNameMap[asnNum]; !ok && asName != "" {
					asnNameMap[asnNum] = asName
				}

				isLiteASN := false
				for _, asns := range preciseASNs {
					if asns[asnStr] {
						isLiteASN = true
						break
					}
				}
				if !isLiteASN {
					if cfSet != nil && cfSet.ContainsPrefix(prefix) {
						isLiteASN = true
					} else if cfFrontSet != nil && cfFrontSet.ContainsPrefix(prefix) {
						isLiteASN = true
					}
				}

				if isLiteASN {
					asnMapLite[asnNum] = append(asnMapLite[asnNum], prefix)
				}
			}
		}
	}

	fmt.Printf("✅ Processed %d records in %v\n", rowCount, time.Since(startTime))

	fmt.Println("🧩 Aggregating & merging CIDR ranges with IPSet...")
	for cc, list := range countryFull {
		countryFull[cc] = mergePrefixes(list)
	}
	for cc, list := range countryLite {
		countryLite[cc] = mergePrefixes(list)
	}
	for tag, list := range serviceFull {
		serviceFull[tag] = mergePrefixes(list)
	}
	for tag, list := range serviceLite {
		serviceLite[tag] = mergePrefixes(list)
	}

	fmt.Println("📦 Building Country MMDB databases (Full & Lite)...")
	mmdbFull, _ := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		RecordSize:   24,
		IPVersion:    6,
	})
	mmdbLite, _ := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		RecordSize:   24,
		IPVersion:    6,
	})

	for cc, prefixes := range countryFull {
		record := mmdbtype.Map{
			"country":            mmdbtype.Map{"iso_code": mmdbtype.String(cc)},
			"registered_country": mmdbtype.Map{"iso_code": mmdbtype.String(cc)},
		}
		for _, p := range prefixes {
			_ = mmdbFull.Insert(prefixToIPNet(p), record)
		}
	}
	for cc, prefixes := range countryLite {
		record := mmdbtype.Map{
			"country":            mmdbtype.Map{"iso_code": mmdbtype.String(cc)},
			"registered_country": mmdbtype.Map{"iso_code": mmdbtype.String(cc)},
		}
		for _, p := range prefixes {
			_ = mmdbLite.Insert(prefixToIPNet(p), record)
		}
	}

	if f, err := os.Create(filepath.Join(*outputDir, "country.mmdb")); err == nil {
		_, _ = mmdbFull.WriteTo(f)
		f.Close()
	}
	if f, err := os.Create(filepath.Join(*outputDir, "country-lite.mmdb")); err == nil {
		_, _ = mmdbLite.WriteTo(f)
		f.Close()
	}

	fmt.Println("📦 Building GeoLite2-ASN MMDB databases (Full & Lite)...")
	buildASNMMDB := func(outputPath string, amap map[uint32][]netip.Prefix) {
		mmdbASN, _ := mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoLite2-ASN",
			RecordSize:   24,
			IPVersion:    6,
		})
		var asnKeys []uint32
		for k := range amap {
			asnKeys = append(asnKeys, k)
		}
		sort.Slice(asnKeys, func(i, j int) bool { return asnKeys[i] < asnKeys[j] })

		for _, asnNum := range asnKeys {
			prefixes := mergePrefixes(amap[asnNum])
			asName := asnNameMap[asnNum]
			record := mmdbtype.Map{
				"autonomous_system_number":       mmdbtype.Uint32(asnNum),
				"autonomous_system_organization": mmdbtype.String(asName),
			}
			for _, p := range prefixes {
				_ = mmdbASN.Insert(prefixToIPNet(p), record)
			}
		}
		if f, err := os.Create(outputPath); err == nil {
			_, _ = mmdbASN.WriteTo(f)
			f.Close()
		}
	}

	buildASNMMDB(filepath.Join(*outputDir, "GeoLite2-ASN.mmdb"), asnMap)
	buildASNMMDB(filepath.Join(*outputDir, "GeoLite2-ASN-lite.mmdb"), asnMapLite)

	fmt.Println("📦 Building MetaDB (Mihomo) and DB (Sing-box)...")
	buildMetaAndSingDB(filepath.Join(*outputDir, "geoip.metadb"), filepath.Join(*outputDir, "geoip.db"), countryFull, serviceFull)
	buildMetaAndSingDB(filepath.Join(*outputDir, "geoip-lite.metadb"), filepath.Join(*outputDir, "geoip-lite.db"), countryLite, serviceLite)

	fmt.Println("📦 Building V2Ray geoip.dat (Full & Lite)...")
	geoipDatFull := buildV2RayGeoIPList(countryFull, serviceFull)
	if err := saveProto(filepath.Join(*outputDir, "geoip.dat"), geoipDatFull); err != nil {
		fmt.Printf("❌ Failed to write geoip.dat: %v\n", err)
	}

	geoipDatLite := buildV2RayGeoIPList(countryLite, serviceLite)
	if err := saveProto(filepath.Join(*outputDir, "geoip-lite.dat"), geoipDatLite); err != nil {
		fmt.Printf("❌ Failed to write geoip-lite.dat: %v\n", err)
	}

	fmt.Printf("🎉 All GeoIP & ASN assets successfully built in %v!\n", time.Since(startTime))
}

func buildMetaAndSingDB(metaPath, singPath string, countryMap, serviceMap map[string][]netip.Prefix) {
	writerMeta, _ := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "Meta-geoip0",
		IPVersion:               6,
		RecordSize:              24,
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})
	writerSing, _ := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "sing-geoip",
		IPVersion:               6,
		RecordSize:              24,
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})

	var included []netip.Prefix
	codeMap := make(map[netip.Prefix][]string)

	addPrefix := func(p netip.Prefix, code string) {
		if len(codeMap[p]) == 0 {
			included = append(included, p)
		}
		codeMap[p] = append(codeMap[p], code)
	}

	for cc, prefixes := range countryMap {
		code := strings.ToLower(cc)
		for _, p := range prefixes {
			addPrefix(p, code)
		}
	}
	for tag, prefixes := range serviceMap {
		code := strings.ToLower(tag)
		for _, p := range prefixes {
			addPrefix(p, code)
		}
	}

	sort.Slice(included, func(i, j int) bool {
		return included[i].Bits() < included[j].Bits()
	})

	for _, p := range included {
		ipNet := prefixToIPNet(p)
		codes := codeMap[p]
		
		_ = writerSing.Insert(ipNet, mmdbtype.String(codes[len(codes)-1]))

		_, existingRecord := writerMeta.Get(ipNet.IP)
		
		var newSlice []mmdbtype.DataType
		if s, ok := existingRecord.(mmdbtype.String); ok {
			newSlice = append(newSlice, s)
		} else if sl, ok := existingRecord.(mmdbtype.Slice); ok {
			newSlice = append(newSlice, sl...)
		}
		
		for _, c := range codes {
			newSlice = append(newSlice, mmdbtype.String(c))
		}

		seen := make(map[string]bool)
		var finalSlice mmdbtype.Slice
		for _, item := range newSlice {
			if str, ok := item.(mmdbtype.String); ok {
				if !seen[string(str)] {
					seen[string(str)] = true
					finalSlice = append(finalSlice, item)
				}
			}
		}

		var record mmdbtype.DataType
		if len(finalSlice) == 1 {
			record = finalSlice[0]
		} else {
			record = finalSlice
		}

		_ = writerMeta.Insert(ipNet, record)
	}

	if f, err := os.Create(metaPath); err == nil {
		_, _ = writerMeta.WriteTo(f)
		f.Close()
	}
	if f, err := os.Create(singPath); err == nil {
		_, _ = writerSing.WriteTo(f)
		f.Close()
	}
}

func fetchCloudflareIPs() []netip.Prefix {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.cloudflare.com/client/v4/ips")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var res struct {
			Result struct {
				IPv4CIDRs []string `json:"ipv4_cidrs"`
				IPv6CIDRs []string `json:"ipv6_cidrs"`
			} `json:"result"`
			Success bool `json:"success"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && res.Success {
			var prefixes []netip.Prefix
			for _, s := range append(res.Result.IPv4CIDRs, res.Result.IPv6CIDRs...) {
				if p, err := netip.ParsePrefix(s); err == nil {
					prefixes = append(prefixes, p)
				}
			}
			if len(prefixes) > 0 {
				fmt.Printf("✅ Fetched %d official Cloudflare CIDRs from API\n", len(prefixes))
				return prefixes
			}
		}
	}
	fmt.Println("⚠️ Using fallback official Cloudflare CIDRs")
	var prefixes []netip.Prefix
	for _, s := range fallbackCloudflareCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

func fetchCloudFrontIPs() []netip.Prefix {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()

	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil
	}

	var prefixes []netip.Prefix
	for _, item := range doc.Prefixes {
		if item.Service == "CLOUDFRONT" && !strings.HasPrefix(strings.ToLower(item.Region), "cn-") {
			if p, err := netip.ParsePrefix(item.IPPrefix); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	for _, item := range doc.IPv6Prefixes {
		if item.Service == "CLOUDFRONT" && !strings.HasPrefix(strings.ToLower(item.Region), "cn-") {
			if p, err := netip.ParsePrefix(item.IPv6Prefix); err == nil {
				prefixes = append(prefixes, p)
			}
		}
	}
	if len(prefixes) > 0 {
		fmt.Printf("✅ Fetched %d official CloudFront CIDRs (Non-CN) from AWS API\n", len(prefixes))
	}
	return prefixes
}

func mergePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	var builder netipx.IPSetBuilder
	for _, p := range prefixes {
		builder.AddPrefix(p)
	}
	s, err := builder.IPSet()
	if err != nil {
		return prefixes
	}
	return s.Prefixes()
}

func buildV2RayGeoIPList(countryMap map[string][]netip.Prefix, serviceMap map[string][]netip.Prefix) *v2raygeo.GeoIPList {
	list := &v2raygeo.GeoIPList{}

	var cKeys []string
	for k := range countryMap {
		cKeys = append(cKeys, k)
	}
	sort.Strings(cKeys)

	for _, k := range cKeys {
		prefixes := countryMap[k]
		entry := &v2raygeo.GeoIP{CountryCode: k}
		for _, p := range prefixes {
			addr := p.Addr()
			var ipBytes []byte
			if addr.Is4() {
				b4 := addr.As4()
				ipBytes = b4[:]
			} else {
				b16 := addr.As16()
				ipBytes = b16[:]
			}
			entry.Cidr = append(entry.Cidr, &v2raygeo.CIDR{
				Ip:     ipBytes,
				Prefix: uint32(p.Bits()),
			})
		}
		list.Entry = append(list.Entry, entry)
	}

	var sKeys []string
	for k := range serviceMap {
		sKeys = append(sKeys, k)
	}
	sort.Strings(sKeys)

	for _, k := range sKeys {
		prefixes := serviceMap[k]
		entry := &v2raygeo.GeoIP{CountryCode: strings.ToUpper(k)}
		for _, p := range prefixes {
			addr := p.Addr()
			var ipBytes []byte
			if addr.Is4() {
				b4 := addr.As4()
				ipBytes = b4[:]
			} else {
				b16 := addr.As16()
				ipBytes = b16[:]
			}
			entry.Cidr = append(entry.Cidr, &v2raygeo.CIDR{
				Ip:     ipBytes,
				Prefix: uint32(p.Bits()),
			})
		}
		list.Entry = append(list.Entry, entry)
	}

	return list
}

func saveProto(filepath string, list *v2raygeo.GeoIPList) error {
	data, err := proto.Marshal(list)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0o644)
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	if addr.Is4() {
		b := addr.As4()
		ip := net.IP(b[:])
		mask := net.CIDRMask(p.Bits(), 32)
		return &net.IPNet{IP: ip, Mask: mask}
	} else {
		b := addr.As16()
		ip := net.IP(b[:])
		mask := net.CIDRMask(p.Bits(), 128)
		return &net.IPNet{IP: ip, Mask: mask}
	}
}
