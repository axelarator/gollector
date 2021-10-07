package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/cavaliercoder/grab"
	"github.com/spf13/cobra"
)

type Host struct {
	RegionCode  string   `json:"region_code"`
	IP          int      `json:"ip"`
	AreaCode    int      `json:"area_code"`
	Latitude    float64  `json:"latitude"`
	Hostnames   []string `json:"hostnames"`
	PostalCode  string   `json:"postal_code"`
	DmaCode     int      `json:"dma_code"`
	CountryCode string   `json:"country_code"`
	Org         string   `json:"org"`
	Data        []struct {
		Product string `json:"product"`
		Title   string `json:"title"`
		Opts    struct {
		} `json:"opts"`
		Timestamp string   `json:"timestamp"`
		Isp       string   `json:"isp"`
		Cpe       []string `json:"cpe"`
		Data      string   `json:"data"`
		HTML      string   `json:"html"`
		Location  struct {
			City         string  `json:"city"`
			RegionCode   string  `json:"region_code"`
			AreaCode     int     `json:"area_code"`
			Longitude    float64 `json:"longitude"`
			CountryCode3 string  `json:"country_code3"`
			Latitude     float64 `json:"latitude"`
			PostalCode   string  `json:"postal_code"`
			DmaCode      int     `json:"dma_code"`
			CountryCode  string  `json:"country_code"`
			CountryName  string  `json:"country_name"`
		} `json:"location"`
		SSL struct {
			Cert struct {
				SslFingerprint struct {
					SHA1   string `json:"sha1"`
					SHA256 string `json:"sha256"`
				}
				Issuer struct {
					C            string `json:"C,omitempty"`
					CN           string `json:"CN,omitempty"`
					DC           string `json:"DC,omitempty"`
					L            string `json:"L,omitempty"`
					O            string `json:"O,omitempty"`
					OU           string `json:"OU,omitempty"`
					SN           string `json:"SN,omitempty"`
					ST           string `json:"ST,omitempty"`
					EmailAddress string `json:"emailAddress,omitempty"`
					SerialNumber string `json:"serialNumber,omitempty"`
				} `json:"issuer"`
				Serial  int `json:"serial"`
				Subject struct {
					CN string `json:"CN"`
				} `json:"subject"`
			} `json:"cert"`
			Ja3s string `json:"ja3s"`
			Jarm string `json:"jarm"`
		} `json:"ssl"`
		IP        int         `json:"ip"`
		Domains   []string    `json:"domains"`
		Org       string      `json:"org"`
		Os        interface{} `json:"os"`
		Port      int         `json:"port"`
		Hostnames []string    `json:"hostnames"`
		IPStr     string      `json:"ip_str"`
	} `json:"data"`
	City         string      `json:"city"`
	Isp          string      `json:"isp"`
	Longitude    float64     `json:"longitude"`
	LastUpdate   string      `json:"last_update"`
	CountryCode3 string      `json:"country_code3"`
	CountryName  string      `json:"country_name"`
	IPStr        string      `json:"ip_str"`
	Os           interface{} `json:"os"`
	Ports        []int       `json:"ports"`
}

// shodanCmd represents the shodan command
var shodanCmd = &cobra.Command{
	Use:   "shodan",
	Short: "Submit an IP to get open ports and check if it's a CS beacon",
	Long: `The submitted IP returns open ports and their services.
An nmap scan is then run using a specified NSE script to check if the IP is a CS beacon. Output is sent to cobalt_output.json which shows beacon config details.`,
	Run: func(cmd *cobra.Command, args []string) {
		shodanKey := os.Getenv("SHODAN_API")
		input := strings.Join(args, " ")
		if shodanKey == "" {
			fmt.Println("Add Shodan API key")
			Setenv("SHODAN_API")
			shodanKey = os.Getenv("SHODAN_API")
		}
		s := New(shodanKey)
		id := make(chan string)
		go s.HostSearch(input, id)
		jarm := <-id
		if jarm != "" {
			s.Pivot(jarm)
		} else {
			fmt.Println("\nJARM isn't in CS list")
		}
	},
}

func init() {
	rootCmd.AddCommand(shodanCmd)
}

var host Host

func (s *Client) HostSearch(q string, jarm chan string) {
	client := http.Client{}
	newJarm := ""
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/shodan/host/%s?key=%s", ShodanURL, q, s.apiKey), nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal([]byte(body), &host)
	if _, err := os.Stat("jarm_cs_202107_uniq_sorted.txt"); err != nil {
		fmt.Println("JARM file not found. Downloading...")
		resp, err := grab.Get(".", "https://raw.githubusercontent.com/carbonblack/active_c2_ioc_public/main/cobaltstrike/JARM/jarm_cs_202107_uniq_sorted.txt")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Download saved to", resp.Filename)
	}
	b, err := ioutil.ReadFile("jarm_cs_202107_uniq_sorted.txt")
	if err != nil {
		panic(err)
	}
	contents := string(b)
	for i := 0; i < len(host.Ports); i++ {
		if host.Data[i].SSL.Jarm != "" {
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			fmt.Printf("Port: %d [%s]\n", host.Data[i].Port, host.Data[i].Product)
			fmt.Println("------------------------------")
			fmt.Printf("Header:\n%s", host.Data[i].Data)
			fmt.Println("------------------------------")
			fmt.Printf("Subject: CN=%s\n", host.Data[i].SSL.Cert.Subject.CN)
			fmt.Printf("Serial: %d\n", host.Data[i].SSL.Cert.Serial)
			fmt.Printf("Jarm: %s\n", host.Data[i].SSL.Jarm)
			fmt.Printf("Ja3s: %s\n", host.Data[i].SSL.Ja3s)
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			// //check whether contents contains substring text
			if strings.Contains(contents, host.Data[i].SSL.Jarm) {
				fmt.Println("JARM FOUND : CS BEACON")
				newJarm = host.Data[i].SSL.Jarm
			}
		} else {
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
			fmt.Printf("Port: %d [%s]\n", host.Data[i].Port, host.Data[i].Product)
			fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
		}
	}
	fmt.Printf("More details here: https://www.shodan.io/host/%s\n", q)
	fmt.Println("----------------------------------------------------")
	fmt.Println("Starting nmap scan")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(q),
		nmap.WithScripts("grab_beacon_config.nse"),
		nmap.WithNmapOutput("cobalt_output.json"),
		nmap.WithVerbosity(10),
		nmap.WithContext(ctx),
	)
	if err != nil {
		log.Fatalf("unable to create scanner: %v", err)
	}

	result, _, err := scanner.Run()

	if err != nil {
		log.Fatalf("unable to run scan: %v", err)
	}

	fmt.Printf("Output written to cobalt_output.json\n%s", result.Stats.Finished.Summary)

	jarm <- newJarm
}

func (s *Client) Pivot(fp string) {
	var query Query
	// Take JARM from output above and pivot to find additional hosts
	client := http.Client{}
	// var unstructured map[string]interface{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/shodan/host/count?key=%s&query=ssl.jarm:%s", ShodanURL, s.apiKey, fp), nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal([]byte(body), &query)
	fmt.Printf("\nHosts using same JARM: %d\n", query.Total)
	fmt.Printf("Find more here: https://www.shodan.io/search?query=ssl.jarm:%s\n", fp)
}
