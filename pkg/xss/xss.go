package xss

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var HtmlInjectionTags = []string{
	`'><i>gr3p`,
	"<s>gr3p",
	`"><b>gr3p`,
}

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

	}
	return result
}

func FindXss(url string, headers []string, timeout int) []string {
	var results []string
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []string{}
	}
	for _, header := range headers {
		parts := strings.Split(header, ":")
		req.Header.Set(parts[0], strings.Join(parts[1:], ":"))
	}
	resp, err := client.Do(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	body_buff, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}
	body := string(body_buff)
	for _, payload := range HtmlInjectionTags {
		if strings.Contains(payload, body) && body != "" {
			fmt.Printf("%s reflection found\n", url)
			results = append(results, url)
		}
	}
	return results

}
