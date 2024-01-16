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
	"github.com/paulbellamy/ratecounter"
)

var (
	wg sync.WaitGroup
)

func main() {
	parser := argparse.NewParser("xss", "Search for xss.")
	headers := parser.StringList("H", "headers", &argparse.Options{Required: false, Help: "Curl like headers"})
	timeout := parser.Int("t", "timeout", &argparse.Options{Required: false, Default: 10, Help: "Request timeout"})
	concurrency := parser.Int("c", "concurrency", &argparse.Options{Required: false, Default: 40, Help: "Limit concurrency"})
	input := parser.String("i", "input", &argparse.Options{Required: false})
	output_file := parser.String("o", "output", &argparse.Options{Required: false})
	rate_limit := parser.Int("r", "rate-limit", &argparse.Options{Required: false, Default: -1, Help: "Limit requests per second"})
	debug := parser.Flag("d", "debug", &argparse.Options{Required: false, Default: false})
	err := parser.Parse(os.Args)
	var results []string
	var inputs_processed int
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		return
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
				counter.Incr(1)
				results = append(results, xss.FindXss(url, *headers, *timeout))
				wg.Done()
				<-semaphore
				if *debug {
					fmt.Printf("\x1b[2K%d requests per second, %d inputs processed\r", counter.Rate(), inputs_processed)
				}
			}(url)

		}
		inputs_processed++

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
	if *debug {
		fmt.Printf("\x1b[2K%d inputs processed\n", inputs_processed)
	}
}
