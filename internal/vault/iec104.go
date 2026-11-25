package vault

import (
	rand "math/rand/v2"
)

type IEC104State struct {
	orgMap    map[uint8]uint8
	orgPool   []uint8
	coaMap    map[uint16]uint16
	coaPool   []uint16
	ioaOffset uint32
}

func NewIEC104State(seed [32]byte) (*IEC104State, error) {
	rng := rand.New(rand.NewChaCha8(seed))

	ioaOff := rng.Uint32N(0x7FFFFF) + 1

	// Fisher-Yates shuffle of ORG pool (1..255, preserves 0)
	orgPool := make([]uint8, 255)
	for i := range 255 {
		orgPool[i] = uint8(i + 1)
	}
	rng.Shuffle(len(orgPool), func(i, j int) {
		orgPool[i], orgPool[j] = orgPool[j], orgPool[i]
	})

	// Fisher-Yates shuffle of COA pool (1..)
	coaPool := make([]uint16, 65534)
	for i := range 65534 {
		coaPool[i] = uint16(i + 1)
	}
	rng.Shuffle(len(coaPool), func(i, j int) {
		coaPool[i], coaPool[j] = coaPool[j], coaPool[i]
	})

	return &IEC104State{
		orgMap:    make(map[uint8]uint8),
		orgPool:   orgPool,
		coaMap:    make(map[uint16]uint16),
		coaPool:   coaPool,
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

	// Get next value from shuffled list
	lastIdx := len(s.orgPool) - 1
	cand := s.orgPool[lastIdx]
	s.orgPool = s.orgPool[:lastIdx]
	s.orgMap[orig] = cand
	return cand
}

func (s *IEC104State) MapCOA(orig uint16) uint16 {
	// Reserved values
	if orig == 0 || orig == 0xFFFF {
		return orig
	}
	if mapped, ok := s.coaMap[orig]; ok {
		return mapped
	}

	// Get next value from shuffled list
	lastIdx := len(s.coaPool) - 1
	cand := s.coaPool[lastIdx]
	s.coaPool = s.coaPool[:lastIdx]
	s.coaMap[orig] = cand
	return cand
}

func (s *IEC104State) MapIOA(ioa uint32) uint32 {
	if ioa == 0 {
		return 0
	}
	return (ioa + s.ioaOffset) & 0xFFFFFF
}

func (s *IEC104State) IOAOffset() uint32 {
	return s.ioaOffset
}
