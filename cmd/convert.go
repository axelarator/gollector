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
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

// convertCmd represents the convert command
var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "encode/decode or sanitize/unsanitize URLs ",
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")
		urle, _ := cmd.Flags().GetBool("urle")
		urld, _ := cmd.Flags().GetBool("urld")
		sanitize, _ := cmd.Flags().GetBool("sanitize")
		unsanitize, _ := cmd.Flags().GetBool("unsanitize")
		if urle {
			UrlEncode(input)
		} else if urld {
			UrlDecode(input)
		} else if sanitize {
			Sanitize(input)
		} else if unsanitize {
			Unsanitize(input)
		}
	},
}

func init() {
	rootCmd.AddCommand(convertCmd)

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	convertCmd.Flags().BoolP("urle", "e", false, "URL encode domain")
	convertCmd.Flags().BoolP("urld", "d", false, "URL decode domain")
	convertCmd.Flags().BoolP("sanitize", "s", false, "Sanitize URL to avoid accidental click")
	convertCmd.Flags().BoolP("unsanitize", "u", false, "Unsanitize URL to click")
}

func UrlEncode(choice string) {
	if strings.Contains(choice, "%") {
		fmt.Println("Already encoded, decoding instead")
		UrlDecode(choice)
	} else {
		encodedValue := url.QueryEscape(choice)
		fmt.Println(encodedValue)
	}
}

func Base64Encode(choice string) {
	encoded := base64.StdEncoding.EncodeToString([]byte(choice))
	fmt.Println(encoded)
}

func UrlDecode(choice string) {
	if !strings.Contains(choice, "%") {
		fmt.Println("Already decoded, encoding instead")
		UrlEncode(choice)
	} else {
		decodedValue, err := url.QueryUnescape(choice)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println(decodedValue)
	}
}

func Base64Decode(input string) {
	decoded64, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Printf("Error decoding %s", err.Error())
	}
	fmt.Println(string(decoded64))
}

func Sanitize(choice string) {
	newInput := strings.Replace(choice, ".", "[.]", -1)
	newInput = strings.Replace(newInput, "tt", "xx", -1)
	fmt.Println(newInput)
}

func Unsanitize(choice string) {
	newInput := strings.Replace(choice, "[.]", ".", -1)
	newInput = strings.Replace(newInput, "xx", "tt", -1)
	fmt.Println(newInput)
}
