package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akamensky/argparse"
	"github.com/joaovitormaia/xss/pkg/xss"
	"github.com/paulbellamy/ratecounter"
)

var (
	wg sync.WaitGroup
)

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

func main() {
	parser := argparse.NewParser("xss", "Search for xss.")
	headers := parser.StringList("H", "headers", &argparse.Options{Required: false, Help: "Curl like headers"})
	timeout := parser.Int("t", "timeout", &argparse.Options{Required: false, Default: 10, Help: "Request timeout"})
	concurrency := parser.Int("c", "concurrency", &argparse.Options{Required: false, Default: 40, Help: "Limit concurrency"})
	input := parser.String("i", "input", &argparse.Options{Required: false})
	output_file := parser.String("o", "output", &argparse.Options{Required: false})
	rate_limit := parser.Int("r", "rate-limit", &argparse.Options{Required: false, Default: -1, Help: "Limit requests per second"})
	debug := parser.Flag("d", "debug", &argparse.Options{Required: false, Default: false})
	debug_folder := parser.String("", "debug-folder", &argparse.Options{Required: false, Help: "Folder to store debug results to"})
	debug_codes := parser.String("", "debug-codes", &argparse.Options{Required: false, Help: "Comma separated http response codes to debug, --debug-folder required. Ex: 302,403"})
	proxy := parser.String("p", "proxy", &argparse.Options{Required: false, Help: "Http proxy config"})
	err := parser.Parse(os.Args)
	if err != nil || (*debug_codes != "" && *debug_folder == "") {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		return
	}
	if *output_file != "" {
		os.Remove(*output_file)
	}
	var inputs_processed int
	var debug_codes_list []int
	if *debug_codes != "" {
		for _, code := range strings.Split(*debug_codes, ",") {
			int_code, err := strconv.Atoi(code)
			if err != nil {
				panic(err)
			}
			debug_codes_list = append(debug_codes_list, int_code)
		}
	}

	var scanner *bufio.Scanner
	if *input != "" {
		file, err := os.Open(*input)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}
	semaphore := make(chan bool, *concurrency)
	period := time.Second / time.Duration(*rate_limit)
	debug_responses := make(chan string)
	// Create a channel to control the rate
	counter := ratecounter.NewRateCounter(1 * time.Second)

	limiter := time.Tick(period)
	for scanner.Scan() {

		input_url := scanner.Text()

		urls := xss.CreateUrls(input_url)
		counter.Incr(1)
		for _, url := range urls {
			if *rate_limit > 0 {
				<-limiter
			}
			wg.Add(1)
			semaphore <- true
			go func(url string) {
				defer wg.Done()
				counter.Incr(1)
				xss_url, vuln := xss.FindXss(url, *headers, *timeout, debug_codes_list, debug_responses, *proxy)
				if vuln && *output_file != "" {
					AppendResultToOutputFile(xss_url, *output_file)
				}
				<-semaphore
				if *debug {
					fmt.Printf("\x1b[2K%d requests per second, %d inputs processed\r", counter.Rate(), inputs_processed)
				}
			}(url)

		}
		inputs_processed++

	}
	wg.Wait()

	if *debug {
		fmt.Printf("\x1b[2K%d inputs processed\n", inputs_processed)
	}
}
