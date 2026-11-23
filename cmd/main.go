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
	v := vault.NewVault([]byte{0x01, 0x02, 0x03, 0x04, 0x05})

	if err := pipeline.Run(inPath, outPath, v); err != nil {
		log.Fatal(err)
	}
}
