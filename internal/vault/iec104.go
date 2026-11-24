package vault

import (
	"crypto/rand"
	"encoding/binary"
)

type IEC104State struct {
	orgMap    map[uint8]uint8
	usedORG   map[uint8]bool
	coaMap    map[uint16]uint16
	usedCOA   map[uint16]bool
	ioaOffset uint32
}

func NewIEC104State() (*IEC104State, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}

	// Random offset for IOA
	ioaOff := (binary.LittleEndian.Uint32(b[:]) % 0xFFFFFF) + 1

	return &IEC104State{
		orgMap:    make(map[uint8]uint8),
		usedORG:   map[uint8]bool{0: true},
		coaMap:    make(map[uint16]uint16),
		usedCOA:   map[uint16]bool{0: true, 0xFFFF: true},
		ioaOffset: ioaOff,
	}, nil
}

// Maps originator 1..255 (1:1) preserves 0
func (s *IEC104State) MapORG(orig uint8) uint8 {
	// Reserved values
	if orig == 0 {
		return 0
	}
	if mapped, ok := s.orgMap[orig]; ok {
		return mapped
	}

	// generate random values until one is free and map to that
	var b [1]byte
	for {
		_, _ = rand.Read(b[:])
		cand := b[0]
		if !s.usedORG[cand] {
			s.usedORG[cand] = true
			s.orgMap[orig] = cand
			return cand
		}
	}
}

func (s *IEC104State) MapCOA(orig uint16) uint16 {
	// Reserved values
	if orig == 0 || orig == 0xFFFF {
		return orig
	}
	if mapped, ok := s.coaMap[orig]; ok {
		return mapped
	}

	// generate random values until one is free and map to that
	var b [2]byte
	for {
		_, _ = rand.Read(b[:])
		cand := binary.LittleEndian.Uint16(b[:])
		if !s.usedCOA[cand] {
			s.usedCOA[cand] = true
			s.coaMap[orig] = cand
			return cand
		}
	}
}

func (s *IEC104State) IOAOffset() uint32 {
	return s.ioaOffset
}
