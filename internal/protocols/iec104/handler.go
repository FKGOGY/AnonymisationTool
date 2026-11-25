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
			if obj.IOAOffset >= 0 && obj.IOA != 0 {
				anonIOA := state.MapIOA(obj.IOA)
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

func shiftCP56Time2a(b []byte, dayShift int, location *time.Location) {
	// b[0..1] - miliseconds <0..59999>
	// b[2] - IV (bit 7) | Res (bit 6) | Minutes <0..59>
	// b[3] - SU (bit 7) | Res2 (bit 5..6) | Hours <0..23>
	// b[4] - DOW (bit 5..7) | Day (bit 0..4) <1..31>
	// b[5] - Res3 (bit 4..7) | Month (Bit 0..3) <1..12>
	// b[6] - Res4 (bit 7) | Year (bit 0..6) <0..99>

	min := int(b[2] & 0x3F)
	hour := int(b[3] & 0x1F)
	origDOW := (b[4] >> 5) & 0x07
	day := int(b[4] & 0x1F)
	month := int(b[5] & 0x0F)
	year := int(b[6] & 0x7F)

	if month < 1 || month > 12 || day < 1 || day > 31 {
		return
	}

	orig := time.Date(2000+year, time.Month(month), day, hour, min, 0, 0, location)
	shifted := orig.AddDate(0, 0, dayShift)

	// Update Summer time bit
	var suBit uint8
	if shifted.IsDST() {
		suBit = 0x80
	}
	b[3] = suBit | (b[3] & 0x7F)

	var newDOW uint8
	if origDOW != 0 {
		newDOW = uint8(shifted.Weekday())
		// in Gos weekday Sunday is 0, Monday is 1, ...
		if newDOW == 0 {
			newDOW = 7
		}
	}
	b[4] = (newDOW << 5) | (uint8(shifted.Day()) & 0x1F)

	b[5] = (b[5] & 0xF0) | (uint8(shifted.Month()) & 0x0F)

	b[6] = (b[6] & 0x80) | uint8(shifted.Year()%100)
}
