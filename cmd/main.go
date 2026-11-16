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
	inPath := "iec104.pcapng"
	outPath := "iec104_out.pcap"
	if len(os.Args) > 1 {
		inPath = os.Args[1]
	}

	v := vault.NewVault()

	if err := pipeline.Run(inPath, outPath, v); err != nil {
		log.Fatal(err)
	}
}
