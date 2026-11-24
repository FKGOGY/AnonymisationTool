// /cmd/main.go
package main

import (
	"log"
	"os"
	"time"

	"github.com/AnonymisationTool/internal/pipeline"
	"github.com/AnonymisationTool/internal/vault"
)

func main() {
	// TEMP file handling
	inPath := "test_files/iec104-extra.pcap"
	outPath := "test_files/iec104-extra_out.pcap"
	if len(os.Args) > 1 {
		inPath = os.Args[1]
	}

	// TODO take seed from configuration file or somewhere
	seed := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	dayShift := 300
	location, err := time.LoadLocation("Europe/Prague")
	v, err := vault.NewVault(seed, dayShift, location)
	if err != nil {
		log.Fatal(err)
	}
	if err := pipeline.Run(inPath, outPath, v); err != nil {
		log.Fatal(err)
	}
}
