/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/domainr/whois"
	"github.com/spf13/cobra"
)

// whoisCmd represents the whois command
var whoisCmd = &cobra.Command{
	Use:   "whois",
	Short: "Whois lookup for a domain",
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")
		fstatus, _ := cmd.Flags().GetBool("rdns")
		if fstatus {
			Rdns(input)
		} else {
			Whois(input)
		}
	},
}

func init() {
	rootCmd.AddCommand(whoisCmd)

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	whoisCmd.Flags().BoolP("rdns", "r", false, "Run RDNS on IP")
}

func Whois(choice string) {

	response, err := whois.Fetch(choice)
	if err != nil {
		fmt.Printf("Enter a valid domain")
	}

	fmt.Println(response)

}

func Rdns(choice string) {

	names, err := net.LookupAddr(choice)
	if err != nil {
		log.Fatal(err)
	}
	if len(choice) == 0 {
		fmt.Printf("No record")
	}
	for _, name := range names {
		fmt.Printf("%s\n", name)
	}
}
