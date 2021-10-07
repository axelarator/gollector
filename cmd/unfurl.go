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
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

// unfurlCmd represents the unfurl command
var unfurlCmd = &cobra.Command{
	Use:   "unfurl",
	Short: "Unfurl a URL to extract obscured information ",
	Run: func(cmd *cobra.Command, args []string) {
		choice := strings.Join(args, " ")
		u, err := url.Parse(choice)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println()
		queries := u.Query()
		fmt.Println("URL: " + choice)
		fmt.Println("Query Strings: ")
		for key, value := range queries {
			fmt.Printf(" %v = %v\n", key, value)
		}
		fmt.Println("Scheme:", u.Scheme,
			"\nHost: ", u.Host,
			"\nPath: ", u.Path,
			"\nFragment: ", u.Fragment,
			"\nRequestURI: ", u.RequestURI())
	},
}

func init() {
	rootCmd.AddCommand(unfurlCmd)
}
