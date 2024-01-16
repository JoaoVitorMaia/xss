package xss

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

var HtmlInjectionTags = []string{
	`'><i>gr3p`,
	"<s>gr3p",
	`"><b>gr3p`,
}

var ReflectedOnTagAtribute = []string{
	`gr3pth1s"`,
	`gr3pth1s'`,
}

var insideTagReflectionRegex = `(?i)<([^<>]*)gr3pth1s["']([^<>]*)>`
var notInComment = `<!--[\s\S]*?gr3pth1s[\s\S]*?-->`

type UrlParameter struct {
	key   string
	value string
}

func CreateUrls(raw_url string) []string {
	result := []string{}
	parsed_url, err := url.Parse(raw_url)
	if err != nil {
		return result
	}
	qs := parsed_url.Query()
	for key, value := range qs {
		for _, payload := range HtmlInjectionTags {
			oldval := value[0] // unfortunately qs.Set() only accepts string not []string, so ?xyz=abc&xyz=3 would only consider abc(resulting on ?xyz=abc)
			qs.Set(key, payload)
			parsed_url.RawQuery = qs.Encode()
			result = append(result, parsed_url.String())
			qs.Set(key, oldval)
		}
		for _, payload := range ReflectedOnTagAtribute {
			oldval := value[0] // unfortunately qs.Set() only accepts string not []string, so ?xyz=abc&xyz=3 would only consider abc(resulting on ?xyz=abc)
			qs.Set(key, payload)
			parsed_url.RawQuery = qs.Encode()
			result = append(result, parsed_url.String())
			qs.Set(key, oldval)
		}

	}
	return result
}
func createDebugString(req http.Request, resp http.Response) string {
	var debug_string []string
	debug_string = append(debug_string, fmt.Sprintf("%s %s %s", req.Method, req.URL.RequestURI(), req.Proto))
	debug_string = append(debug_string, fmt.Sprintf("Host: %s", req.Host))
	for key, values := range req.Header {
		for _, value := range values {
			debug_string = append(debug_string, fmt.Sprintf("%s: %s", key, value))
		}
	}
	debug_string = append(debug_string, "\n")
	debug_string = append(debug_string, "---- ↑ Request ---- Response ↓ ----\n")
	debug_string = append(debug_string, fmt.Sprintf("%s %s", resp.Proto, resp.Status))
	for key, values := range resp.Header {
		for _, value := range values {
			debug_string = append(debug_string, fmt.Sprintf("%s: %s", key, value))
		}
	}
	debug_string = append(debug_string, "\n")
	body_buff, _ := ioutil.ReadAll(resp.Body)
	debug_string = append(debug_string, string(body_buff))
	return strings.Join(debug_string, "\n")
}
func AppendResultToOutputFile(result string, outputfile string) {
	file, err := os.OpenFile(outputfile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()
	if err != nil {
		panic(err)
	}
	file.WriteString(fmt.Sprintf("%s\n", result))
}
func FindXss(url_to_validate string, headers []string, timeout int, debug_codes []int, debug_responses chan string, proxy string, elogfilename string) (string, bool) {
	var client *http.Client
	if proxy == "" {
		client = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
	} else {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			panic(err)
		}
		client = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyUrl),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	req, err := http.NewRequest("GET", url_to_validate, nil)
	if err != nil {
		if elogfilename != "" {
			AppendResultToOutputFile(err.Error(), elogfilename)
		}
		return "", false
	}
	has_user_agent := false
	for _, header := range headers {
		parts := strings.Split(header, ":")
		if parts[0] == "User-Agent" {
			has_user_agent = true
		}
		req.Header.Set(parts[0], strings.Join(parts[1:], ":"))
	}
	if !has_user_agent {
		req.Header.Set("User-Agent", "xss-fuzzer")
	}
	resp, err := client.Do(req)
	if err != nil {
		if elogfilename != "" {
			AppendResultToOutputFile(err.Error(), elogfilename)
		}
		return "", false
	}

	defer resp.Body.Close()

	body_buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if elogfilename != "" {
			AppendResultToOutputFile(err.Error(), elogfilename)
		}
		return "", false
	}
	body := string(body_buff)
	if slices.Contains(debug_codes, resp.StatusCode) {

		debug_responses <- createDebugString(*req, *resp)
	}
	for _, payload := range HtmlInjectionTags {
		if strings.Contains(body, payload) {
			fmt.Printf("%s reflection found\n", url_to_validate)
			return url_to_validate, true
		}
	}
	r, _ := regexp.Compile(insideTagReflectionRegex)
	r2, _ := regexp.Compile(notInComment)
	matches := r.FindStringSubmatch(body)
	if len(matches) > 0 && !r2.MatchString(matches[0]) {
		fmt.Printf("%s reflection found\n", url_to_validate)
		return url_to_validate, true
	}
	return "", false
}
