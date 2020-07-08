package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	target         string
	domain         string
	proto          string
	port           int  = 0
	amazon         bool = false
	amazon_service string
	provider       string
	ovh            bool
	country        string
	timeout        int = 2
	custom_range   string
	cdf_body       string
	//tempfile       string = "TMP." + strconv.Itoa(int(time.Now().Unix()))
	tempfile string = "TMP.tst"
	help     bool   = false
	wg       sync.WaitGroup
	black    = "\033[1;30m"
	eror     = "\033[1;38;5;15;48;5;1m"
	red      = "\033[1;31m"
	green    = "\033[1;32m"
	yellow   = "\033[1;33m"
	purple   = "\033[1;34m"
	magenta  = "\033[1;35m"
	teal     = "\033[1;36m"
	white    = "\033[1;37m"
	blank    = "\033[1;0m"
)

var amazon_ser = []string{"AMAZON", "CHIME_VOICECONNECTOR", "ROUTE53_HEALTHCHECKS", "S3", "DYNAMODB", "EC2", "ROUTE53", "CLOUDFRONT", "CODEBUILD", "GLOBALACCELERATOR", "AMAZON", "AMAZON_CONNECT", "ROUTE53_HEALTHCHECKS_PUBLISHING", "AMAZON", "CLOUDFRONT", "AMAZON", "CHIME_MEETINGS", "AMAZON", "API_GATEWAY", "AMAZON_CONNECT", "CLOUD9", "EC2_INSTANCE_CONNECT", "WORKSPACES_GATEWAYS", "DYNAMODB", "AMAZON_APPFLOW", "EC2_INSTANCE_CONNECT"}

var country_lst = []string{"ad", "ae", "af", "ag", "ai", "al", "am", "ao", "ap", "aq", "ar", "as", "at", "au",
	"aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs", "bt", "bw", "by", "bz", "ca", "cd", "cf", "cg", "ch", "ci", "ck", "cl",
	"cm", "cn", "co", "cr", "cu", "cv", "cw", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz", "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb", "gd",
	"ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gt", "gu", "gw", "gy", "hk", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je",
	"jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me", "mf", "mg",
	"mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om", "pa",
	"pe", "pf", "pg", "ph", "pk", "pl", "pm", "pr", "ps", "pt", "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "so", "sr",
	"ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tst", "tt", "tv", "tw", "tz", "ua", "ug", "us", "uy", "uz", "va", "vc", "ve", "vg",
	"vi", "vn", "vu", "wf", "ws", "ye", "yt", "za", "zm", "zw"}

func args() {
	flag.StringVar(&target, "target", "", "URL with protocol")
	flag.StringVar(&target, "t", "", "alias for --target")
	flag.IntVar(&port, "port", 0, "Port numer")
	flag.IntVar(&port, "p", port, "alias for --port")
	flag.BoolVar(&amazon, "amazon", false, "Check only amazon ip")
	flag.BoolVar(&amazon, "a", false, "Alias for --amazon")
	flag.StringVar(&amazon_service, "amazon-service", "", "Check for specific amazon service")
	flag.StringVar(&amazon_service, "s", "", "Check for this specific amazon service")
	flag.BoolVar(&ovh, "ovh", false, "Check only ovh Cluster")
	flag.BoolVar(&ovh, "o", false, "Check only ovh Cluster")
	flag.StringVar(&country, "contry", "", "[2 letters] Check all ip from contry")
	flag.StringVar(&country, "c", "", "[2 letters] Check all ip from contry")
	flag.IntVar(&timeout, "timeout", 2, "Timeout in second for cURL")
	flag.IntVar(&timeout, "T", 2, "Timeout in second for cURL")
	flag.StringVar(&custom_range, "custom-range", "", "Custom ip range")
	flag.StringVar(&custom_range, "C", "", "Custom ip range")
	flag.BoolVar(&help, "help", false, "print this help message")
	flag.BoolVar(&help, "h", false, "print this help message")
	flag.Parse()
	if flag.NFlag() == 0 {
		usage()
		os.Exit(0)
	}
}

func usage() {
	usage := `Find real ip behind cloudflaire
usage: 
  -t, --target [URL]              URL with protocol (http://, https://)
  -p, --port   [PORT]             Specify port 
  -a, --amazon                    Check only amazon ips
  -s, --amazon-service [SERVICE]  Specify amazon service (EC2)
  -o, --ovh                       Check only ovh (cluster only)
  -c, --country [COUNTRY CODE]    Check all ip of country 
                                    (don't work with -a, -o, -s, -C)
  -T, --timeout [second]          Timeout in second for curl 
  -C, --custom-range [RANGE]      Custom ip range

exemples:
  ./discloudflR -t https://xxxxx.ch -T 2.5
      Scan 0.0.0.0 (Very long) with timeout to 2.5 for each requests

  ./discloudflR -t https://xxxxx.ch -c ch
      Scan all ip from switzerland

  ./discloudflR -t https://xxxxx.ch -C X.X.X.X/24
      Scan the custom range X.X.X.X/24

  ./discloudflR -t https://xxxxx.ch -a -s 'EC2'
      Scan only amazon EC2 ips`
	fmt.Println(usage)
}

func check_args() {
	if help == true {
		usage()
		os.Exit(0)
	}
	if target == "" {
		fmt.Println(eror, "Error:", blank, red, "\n\tYou must provide a target ! [-t https://xxxx.ch]", blank)
		usage()
		os.Exit(1)
	}
	if !(strings.Contains(target, "https://") ||
		strings.Contains(target, "http://")) {
		fmt.Println(eror, "Error:", blank, red, "\n\tYou should pass the protocol (http:// or https://)", blank)
		os.Exit(1)
	}
	u, _ := url.Parse(target)
	domain = u.Host
	proto = u.Scheme
	if port == 0 {
		port = set_port(proto)
	}

	// AMAZON SERVICE
	if amazon_service != "" {
		if !strings.Contains(strings.Join(amazon_ser, " "), strings.ToUpper(amazon_service)) {
			fmt.Println(eror, "Error:", blank, red, "\nAmazon service should be in:\n", amazon_ser)
			os.Exit(1)
		}
	}

	// Country CHECK
	if country != "" {
		if !strings.Contains(strings.Join(country_lst, " "), country[0:2]) {
			fmt.Println(eror, "Error:", blank, red, "\nSelect a valid country code. ex: 'ch'")
			os.Exit(1)
		}
	}
}

func set_port(proto string) int {
	if proto == "http" {
		port := 80
		return port
	} else if proto == "https" {
		port := 443
		return port
	}
	return port
}

func set_provider() string {
	if amazon_service != "" {
		provider := "amazon_service"
		return provider
	} else if ovh {
		provider := "ovh"
		return provider
	} else if custom_range != "" {
		provider := "custom"
		return provider
	} else if country != "" {
		provider := "country"
		return provider
	} else if amazon {
		provider := "amazon"
		return provider
	} else {
		provider := "wild"
		return provider
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cidr_to_ip(cidr string) []string {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips

	default:
		return ips[1 : len(ips)-1]
	}
}

func amazon_scan(s string) {
	type Amz []struct {
		Ip_prefix string `json:"ip_prefix"`
		Region    string `json:"region"`
		Service   string `json:"service"`
		Network   string `json:"network_border_group"`
	}
	jsn, _ := os.Open("amazon.txt")
	js, _ := ioutil.ReadAll(jsn)
	defer jsn.Close()
	var ip Amz
	json.Unmarshal([]byte(js), &ip)
	for i := 0; i < len(ip); i++ {
		if s != "" && strings.ToUpper(s) != ip[i].Service {
			continue
		} else if s != "" && strings.ToUpper(s) == ip[i].Service {
			fmt.Printf("\r", ip[i].Ip_prefix, "    ")
			custom := cidr_to_ip(ip[i].Ip_prefix)
			wg.Add(len(custom))
			for i := 0; i < len(custom); i++ {
				go resolved_get(custom[i], domain, proto, cdf_body)
			}
		} else {
			fmt.Printf("\r", ip[i].Ip_prefix, "    ")
			custom := cidr_to_ip(ip[i].Ip_prefix)
			wg.Add(len(custom))
			for i := 0; i < len(custom); i++ {
				go resolved_get(custom[i], domain, proto, cdf_body)
			}
		}
		wg.Wait()
	}
}

func ovh_scan() {
	file, _ := os.Open("ovh.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	wg.Add(261)
	for scanner.Scan() {
		go resolved_get(scanner.Text(), domain, proto, cdf_body)
	}
	wg.Wait()
}

func country_scan(country_code string) {
	country_file := "country/" + country_code[0:2]
	file, _ := os.Open(country_file)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	wgn := 0
	for scanner.Scan() {
		wgn++
	}
	wg.Add(wgn)
	for scanner.Scan() {
		fmt.Printf("\r", scanner.Text(), "     ")
		go resolved_get(scanner.Text(), domain, proto, cdf_body)
	}
	wg.Wait()
}

func custom_ip(cust string) {
	custom := cidr_to_ip(cust)
	wg.Add(len(custom))
	for i := 0; i < len(custom); i++ {
		go resolved_get(custom[i], domain, proto, cdf_body)
	}
	wg.Wait()
}

func wild_scan() {
	for i := 1; i < 256; i++ {
		for j := 0; j < 256; j++ {
			for k := 0; k < 256; k++ {
				ipgen := strconv.Itoa(i) + "." + strconv.Itoa(j) + "." + strconv.Itoa(k) + ".0/24"
				fmt.Print("\r", ipgen, "   ")
				ips := cidr_to_ip(ipgen)
				wg.Add(len(ips))
				for i := 0; i < len(ips); i++ {
					go resolved_get(ips[i], domain, proto, cdf_body)
				}
				wg.Wait()
			}
		}
	}
}

func resolved_get(targt_ip string, domain string, proto string, cdf_body string) {
	defer wg.Done()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tgt := proto + "://" + targt_ip
	req, _ := http.NewRequest("GET", tgt, nil)
	req.Host = domain
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Join(resp.Header["Server"], "") == "cloudflare" {
		return
	} else if strings.Join(resp.Header["Server"], "") != "cloudflare" {
		if string(body) == cdf_body {
			fmt.Println("SUCCESS:\n", "[", proto, "://", domain, "]--->[", targt_ip, "]")
			os.Exit(0)

		}
	}
}

func original_get(target string, proto string) string {
	resp, err := http.Get(proto + "://" + domain + ":" + strconv.Itoa(port))
	if err != nil {
		fmt.Printf("ERROR:\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Join(resp.Header["Server"], "") != "cloudflare" {
		fmt.Println("Error: Target dont use cloudflare")
		os.Exit(1)
	}
	if len(body) == 0 {
		fmt.Println("ERROR: Body size is 0")
		os.Exit(1)
	} else if string(body) == "Forbidden" {
		fmt.Println("ERROR: Forbidden")
		os.Exit(1)
	}
	return string(body)
}

func main() {
	args()
	check_args()
	provider := set_provider()
	cdf_body = original_get(domain, proto)
	if provider == "custom" {
		custom_ip(custom_range)
	} else if provider == "amazon" || provider == "amazon_service" {
		amazon_scan(amazon_service)
	} else if provider == "ovh" {
		ovh_scan()
	} else if provider == "country" {
		country_scan(country)
	} else if provider == "wild" {
		wild_scan()
	}
}
