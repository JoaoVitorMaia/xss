package xss

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
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

func FindXss(url_to_validate string, headers []string, timeout int, debug_codes []int, debug_responses chan string, proxy string) (string, bool) {
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
				Proxy: http.ProxyURL(proxyUrl),
			},
		}
	}
	req, err := http.NewRequest("GET", url_to_validate, nil)
	if err != nil {
		return "", false
	}
	for _, header := range headers {
		parts := strings.Split(header, ":")
		req.Header.Set(parts[0], strings.Join(parts[1:], ":"))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	body_buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	body := string(body_buff)
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
