package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/axelarator/gollector/cmd"
)

func main() {
	shodanKey := os.Getenv("SHODAN_API")
	vtKey := os.Getenv("VT_API")

	if shodanKey == "" {
		fmt.Println("Add Shodan API key")
		cmd.Setenv("SHODAN_API")
		shodanKey = os.Getenv("SHODAN_API")
	}

	if vtKey == "" {
		fmt.Println("Add VirusTotal API key")
		cmd.Setenv("VT_API")
		vtKey = os.Getenv("VT_API")
	}

	shodan := flag.NewFlagSet("shodan", flag.ExitOnError)
	vt := flag.NewFlagSet("vt", flag.ExitOnError)
	choice := os.Args[2]

	switch os.Args[1] {
	case "shodan":
		shodan.Parse(os.Args[2:])
		s := cmd.New(shodanKey)
		id := make(chan string)
		go s.HostSearch(choice, id)
		jarm := <-id
		if jarm != "" {
			s.Pivot(jarm)
		} else {
			fmt.Println("\nJARM isn't in CS list")
		}
	case "vt":
		vt.Parse(os.Args[2:])
		v := cmd.New(vtKey)
		v.VTLookup(choice)
	case "help":
		fmt.Println("$ binary <command> <url/domain/hash>")
		fmt.Println("Commands:")
		fmt.Println("\tshodan [Submit IP to shodan with ability to pivot on JARM signature]")
		fmt.Println("\tvt [Submit a url/hash/ip to VirusTotal]")
	default:
		fmt.Println("shodan or vt expected. Exiting")
		os.Exit(1)
	}

}
