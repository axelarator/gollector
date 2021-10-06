package cmd

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"
)

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

func Unfurl(choice string) {
	u, err := url.Parse(choice)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println()
	queries := u.Query()
	fmt.Println("Query Strings: ")
	for key, value := range queries {
		fmt.Printf(" %v = %v\n", key, value)
	}
	fmt.Println("Scheme:", u.Scheme,
		"\nHost: ", u.Host,
		"\nPath: ", u.Path,
		"\nFragment: ", u.Fragment,
		"\nRequestURI: ", u.RequestURI())
}
