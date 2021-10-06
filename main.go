package main

import (
	"fmt"
	"os"

	"github.com/axelarator/gollector/cmd"
)

func main() {
	shodanKey := os.Getenv("SHODAN_API")
	vtKey := os.Getenv("VT_API")

	// find a better way to use arguments
	choice := os.Args[2]

	if shodanKey == "" {
		fmt.Println("Add Shodan API key")
		cmd.Setenv("SHODAN_API")
		shodanKey = os.Getenv("SHODAN_API")
	}
	if vtKey == "" {
		fmt.Println("Add VirusTotal API key")
		cmd.Setenv("VT_API")
		shodanKey = os.Getenv("VT_API")
	}
	s := cmd.New(shodanKey)
	v := cmd.New(vtKey)
	id := make(chan string)
	go s.HostSearch(choice, id)
	v.VTLookup(choice)
	jarm := <-id
	if jarm != "" {
		s.Pivot(jarm)
	} else {
		fmt.Println("\nJARM isn't in CS list")
	}
}
