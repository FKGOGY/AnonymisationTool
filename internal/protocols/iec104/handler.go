// /internal/protocols/iec104/handler.go
package iec104

import (
	"encoding/binary"
	"errors"

	"github.com/AnonymisationTool/internal/protocols"
	"github.com/AnonymisationTool/internal/vault"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const Port = 2404

type Handler struct{}

func (Handler) Name() string { return "iec104" }

func (Handler) Match(pkt gopacket.Packet) bool {
	if !protocols.TCPPort(pkt, Port) {
		return false
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	payload := tcpLayer.(*layers.TCP).Payload
	return len(payload) >= 6 && payload[0] == StartByte
}

func (Handler) Anonymize(payload []byte, v *vault.Vault) ([]byte, error) {
	out := make([]byte, len(payload))
	copy(out, payload)

	frames, err := Dissect(out)
	if err != nil && !errors.Is(err, ErrTruncated) {
		return nil, err
	}

	for _, fr := range frames {
		if fr.ASDU == nil {
			continue // S and U frames carry no ASDU identifiers
		}
		h := fr.ASDU

		// Originator Address (0 = unused)
		if h.Originator != 0 {
			out[h.OriginatorOffset] = uint8(1) // map
		}

		// Common Address (2 bytes)
		anonCA := uint16(1) // map
		binary.LittleEndian.PutUint16(out[h.CommonAddrOffset:h.CommonAddrOffset+2], anonCA)

		// Information Objects (3-byte IOA + optional 7-byte CP56Time2a)
		for _, obj := range h.Objects {
			if obj.IOAOffset >= 0 {
				anonIOA := 1 // map
				out[obj.IOAOffset] = byte(anonIOA)
				out[obj.IOAOffset+1] = byte(anonIOA >> 8)
				out[obj.IOAOffset+2] = byte(anonIOA >> 16)
			}
			if obj.TimeOffset >= 0 {
				shiftCP56Time2a(out[obj.TimeOffset:obj.TimeOffset+7], v)
			}
		}
	}

	return out, nil
}

func shiftCP56Time2a(b []byte, v *vault.Vault) {
	// TODO
}
