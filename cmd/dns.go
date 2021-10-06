package cmd

import (
	"fmt"
	"log"
	"net"

	"github.com/domainr/whois"
)

func Whois(choice string) {

	// request, err := whois.NewRequest(choice)
	// if err != nil {
	// 	fmt.Printf("Enter a valid domain")
	// }

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
