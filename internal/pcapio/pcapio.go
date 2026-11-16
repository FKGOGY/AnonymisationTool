// /internal/pcapio/pcapio.go
// Opens classic pcap and pcapng files behind one interface
package pcapio

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Source returns raw packets one at a time
type Source interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

var pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

// Detects the format from the first four bytes (pcapng section header block vs classic pcap magic)
func Open(r io.Reader) (Source, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("reading capture header: %w", err)
	}
	if bytes.Equal(magic, pcapngMagic) {
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("opening pcapng: %w", err)
		}
		return ng, nil
	}
	rd, err := pcapgo.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("opening pcap: %w", err)
	}
	return rd, nil
}

// Create and initializes a PCAP writer with an Ethernet global header
func Create(w io.Writer) (*pcapgo.Writer, error) {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return nil, fmt.Errorf("writing pcap header: %w", err)
	}
	return pw, nil
}
