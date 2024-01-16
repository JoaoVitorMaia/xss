package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akamensky/argparse"
	"github.com/joaovitormaia/xss/pkg/xss"
)

var (
	wg sync.WaitGroup
)

func main() {
	parser := argparse.NewParser("xss", "Search for xss.")
	headers := parser.StringList("H", "headers", &argparse.Options{Required: false, Help: "Curl like headers"})
	timeout := parser.Int("t", "timeout", &argparse.Options{Required: false, Default: 10, Help: "Request timeout"})
	concurrency := parser.Int("c", "concurrency", &argparse.Options{Required: false, Default: 40, Help: "Limit concurrency"})
	filename := parser.String("f", "file", &argparse.Options{Required: false})
	output_file := parser.String("o", "output", &argparse.Options{Required: false})
	rate_limit := parser.Int("r", "rate-limit", &argparse.Options{Required: false, Default: -1, Help: "Limit requests per second"})
	err := parser.Parse(os.Args)
	var results []string
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		return
	}
	var scanner *bufio.Scanner
	if *filename != "" {
		file, err := os.Open(*filename)
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

	// Create a channel to control the rate
	limiter := time.Tick(period)
	for scanner.Scan() {

		input_url := scanner.Text()

		urls := xss.CreateUrls(input_url)
		for _, url := range urls {
			if *rate_limit > 0 {
				<-limiter
			}
			wg.Add(1)
			semaphore <- true
			go func(url string) {
				results = append(results, xss.FindXss(url, *headers, *timeout)...)
				wg.Done()
				<-semaphore
			}(url)

		}

	}
	wg.Wait()
	if *output_file != "" {
		file, err := os.Create(*output_file)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		file.WriteString(strings.Join(results, "\n"))
	}
}
