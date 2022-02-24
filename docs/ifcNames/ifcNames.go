package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for i, s := range devices {
		if s.Description == "" {
			fmt.Printf("[%v] %v\n", i, s.Name)
		} else {
			fmt.Printf("[%v] %v (%v)\n", i, s.Name, s.Description)
		}
	}
}
