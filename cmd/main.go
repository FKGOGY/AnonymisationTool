// /cmd/main.go
package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnonymisationTool/internal/pipeline"
	"github.com/AnonymisationTool/internal/vault"
)

func main() {
	// TEMP arg and file handling
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <input_file>\n", os.Args[0])
		os.Exit(1)
	}

	inPath := os.Args[1]
	ext := filepath.Ext(inPath)
	outPath := strings.TrimSuffix(inPath, ext) + "_out" + ext

	// TODO take these from a config file or somewhere
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		log.Fatal(err)
	}

	dayShift := 970
	location := time.UTC
	v, err := vault.NewVault(seed, dayShift, location)
	if err != nil {
		log.Fatal(err)
	}
	if err := pipeline.Run(inPath, outPath, v); err != nil {
		log.Fatal(err)
	}
}
