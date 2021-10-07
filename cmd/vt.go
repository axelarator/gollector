package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const ShodanURL string = "https://api.shodan.io"
const VtURL string = "https://www.virustotal.com/api/v3"

type Query struct {
	Matches []string `json:"matches"`
	Total   int      `json:"total"`
}

type FullList struct {
	FullList []struct {
		Attribute struct {
			Type  string `json:"type_description"`
			Name  string `json:"meaningful_name"`
			Magic string `json:"magic"`
			Whois string `json:"whois"`
			Stats struct {
				Malicious int `json:"malicious"`
			} `json:"last_analysis_stats"`
			ASN      int    `json:"asn"`
			AS_Owner string `json:"as_owner"`
			Sha256   struct {
				Fingerprint string `json:"thumbprint_sha256"`
			} `json:"last_https_certificate"`
		} `json:"attributes"`
		Type  string `json:"type"`
		Links []struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
	Meta struct {
		Count int `json:"count"`
	} `json:"meta"`
}

// vtCmd represents the vt command
var vtCmd = &cobra.Command{
	Use:   "vt",
	Short: "Uses VT API to get relevant information",
	Long: `Input is first run against a standard VT search for quick analysis.
If the input is a file, a second request is sent to check if that file is executed by any other files. This is denoted by the 'Count' output`,
	Run: func(cmd *cobra.Command, args []string) {
		vtKey := os.Getenv("VT_API")
		input := strings.Join(args, " ")
		if vtKey == "" {
			fmt.Println("Add VirusTotal API key")
			Setenv("VT_API")
			vtKey = os.Getenv("VT_API")
		}
		v := New(vtKey)
		v.VTLookup(input)
	},
}

func init() {
	rootCmd.AddCommand(vtCmd)

}

type Client struct {
	apiKey string
}

func New(apiKey string) *Client {
	return &Client{apiKey: apiKey}
}

func Setenv(key string) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Key: ")
	scanner.Scan()
	text := scanner.Text()
	os.Setenv(key, text)
}

func (s *Client) VTLookup(key string) {

	var structured FullList
	var structured2 FullList
	client := http.Client{}
	client2 := http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/search?query=%s", VtURL, key), nil)

	// pass a SHA256 hash to return a list of files that executed the given file. Limited to 10 for now
	req2, err := http.NewRequest("GET", fmt.Sprintf("%s/files/%s/execution_parents", VtURL, key), nil)
	req.Header.Set("X-Apikey", s.apiKey)
	req2.Header.Set("X-Apikey", s.apiKey)

	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	resp2, err := client2.Do(req2)
	if err != nil {
		log.Fatal(err)
	}
	defer resp2.Body.Close()
	body2, err := ioutil.ReadAll(resp2.Body)

	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal([]byte(body), &structured)
	json.Unmarshal([]byte(body2), &structured2)

	for i := 0; i < len(structured.FullList); i++ {
		switch structured.FullList[i].Type {
		case "domain":
			fmt.Printf("Malicious score: %d\n", structured.FullList[i].Attribute.Stats.Malicious)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("HTTPS CERT SHA256: %s\n", structured.FullList[i].Attribute.Sha256.Fingerprint)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("ASN: %d\n", structured.FullList[i].Attribute.ASN)
			fmt.Printf("AS_Owner: %s\n", structured.FullList[i].Attribute.AS_Owner)
		case "ip_address":
			fmt.Printf("Malicious score: %d\n", structured.FullList[i].Attribute.Stats.Malicious)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("HTTPS CERT SHA256: %s\n", structured.FullList[i].Attribute.Sha256.Fingerprint)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("ASN: %d\n", structured.FullList[i].Attribute.ASN)
			fmt.Printf("AS_Owner: %s\n", structured.FullList[i].Attribute.AS_Owner)
		case "file":
			fmt.Printf("Malicious score: %d\n", structured.FullList[i].Attribute.Stats.Malicious)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("Magic: %s\n", structured.FullList[i].Attribute.Magic)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("Name: %s\n", structured.FullList[i].Attribute.Name)
			fmt.Println("----------------------------------------------------")
			fmt.Printf("Count: %d\n", structured2.Meta.Count)
		default:
			fmt.Println(structured.FullList[i].Attribute)
		}
	}
}
