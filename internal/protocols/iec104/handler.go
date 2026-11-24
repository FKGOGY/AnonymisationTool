// /internal/protocols/iec104/handler.go
package iec104

import (
	"encoding/binary"
	"errors"
	"time"

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

	state := v.IEC104()
	ioaDelta := state.IOAOffset() // TODO is IOA that sensitive? And what if there are like 10 objects and in the middle we pass MAX_IOA

	for _, fr := range frames {
		if fr.ASDU == nil {
			continue // S and U frames carry no ASDU identifiers
		}
		h := fr.ASDU

		// Originator Address (0 = unused)
		if h.Originator != 0 {
			out[h.OriginatorOffset] = state.MapORG(h.Originator)
		}

		// Common Address (2 bytes)
		anonCA := state.MapCOA(h.CommonAddr)
		binary.LittleEndian.PutUint16(out[h.CommonAddrOffset:h.CommonAddrOffset+2], anonCA)

		// Information Objects (3-byte IOA + optional 7-byte CP56Time2a)
		for _, obj := range h.Objects {
			if obj.IOAOffset >= 0 {
				anonIOA := (obj.IOA + ioaDelta) & 0xFFFFFF
				out[obj.IOAOffset] = byte(anonIOA)
				out[obj.IOAOffset+1] = byte(anonIOA >> 8)
				out[obj.IOAOffset+2] = byte(anonIOA >> 16)
			}
			if obj.TimeOffset >= 0 {
				shiftCP56Time2a(out[obj.TimeOffset:obj.TimeOffset+7], v.DayShift(), v.Location())
			}
		}
	}

	return out, nil
}

func shiftCP56Time2a(b []byte, dayShift int, loc *time.Location) {
	// TODO
}
