package cmd

import (
	"bufio"
	"fmt"
	"os"
)

const ShodanURL string = "https://api.shodan.io"
const VtURL string = "https://www.virustotal.com/api/v3"

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
