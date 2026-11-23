// /cmd/main.go
package main

import (
	"log"
	"os"

	"github.com/AnonymisationTool/internal/pipeline"
	"github.com/AnonymisationTool/internal/vault"
)

func main() {
	// TEMP file handling
	inPath := "test_files/iec104.pcapng"
	outPath := "test_files/iec104_out.pcap"
	if len(os.Args) > 1 {
		inPath = os.Args[1]
	}

	// TODO take seed from configuration file or somewhere
	v, err := vault.NewVault([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	if err != nil {
		log.Fatal(err)
	}
	if err := pipeline.Run(inPath, outPath, v); err != nil {
		log.Fatal(err)
	}
}
