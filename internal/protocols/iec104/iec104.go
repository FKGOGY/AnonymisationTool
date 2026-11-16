// /internal/protocols/iec104/iec104.go
// Disector works only if tcp packet has whole message if they are split between packets error is returned
package iec104

import "errors"

const (
	StartByte     = 0x68
	offControl    = 2
	offASDU       = 6
	asduHeaderLen = 6
)

var (
	ErrLostSync  = errors.New("iec104: payload does not start with 0x68")
	ErrBadLength = errors.New("iec104: invalid APDU length")
	ErrTruncated = errors.New("iec104: APDU continues in the next TCP segment")
)

type Format uint8

const (
	FormatI Format = iota
	FormatS
	FormatU
)

func (f Format) String() string {
	switch f {
	case FormatI:
		return "I"
	case FormatS:
		return "S"
	default:
		return "U"
	}
}

type APCI struct {
	Format  Format
	Length  int
	SendSeq uint16
	RecvSeq uint16
	Control [4]byte
}

type InfoObject struct {
	IOA        uint32
	IOAOffset  int // Byte offset in payload (-1 when SQ=true and object index > 0)
	TimeOffset int // Byte offset of 7-byte CP56Time2a in payload (-1 if none)
}

type ASDUHeader struct {
	TypeID           uint8
	SQ               bool
	NumObjects       uint8
	Cause            uint8
	Negative         bool
	Test             bool
	Originator       uint8
	OriginatorOffset int
	CommonAddr       uint16
	CommonAddrOffset int
	Objects          []InfoObject
}

type Frame struct {
	APCI APCI
	ASDU *ASDUHeader
}

// Splits one TCP payload into APDUs and records byte offsets
func Dissect(payload []byte) ([]Frame, error) {
	var frames []Frame
	for pos := 0; pos < len(payload); {
		rest := payload[pos:]
		if rest[0] != StartByte {
			return frames, ErrLostSync
		}
		if len(rest) < 2 {
			return frames, ErrTruncated
		}
		// Min APDU length
		if rest[1] < 4 {
			return frames, ErrBadLength
		}
		total := int(rest[1]) + 2
		if len(rest) < total {
			return frames, ErrTruncated
		}

		// Pass position so all offsets are relative to start of payload
		f, err := dissectAPDU(rest[:total], pos)
		if err != nil {
			return frames, err
		}
		frames = append(frames, f)
		pos += total
	}
	return frames, nil
}

// Dissects single APDU
func dissectAPDU(b []byte, baseOff int) (Frame, error) {
	c := b[offControl:offASDU]
	a := APCI{Length: int(b[1])}
	copy(a.Control[:], c)

	switch {
	case c[0]&0x01 == 0:
		a.Format = FormatI
		a.SendSeq = uint16(c[0]>>1) | uint16(c[1])<<7
		a.RecvSeq = uint16(c[2]>>1) | uint16(c[3])<<7
	case c[0]&0x03 == 0x01:
		a.Format = FormatS
		a.RecvSeq = uint16(c[2]>>1) | uint16(c[3])<<7
	default:
		a.Format = FormatU
	}

	f := Frame{APCI: a}
	if a.Format != FormatI {
		return f, nil // S nad U frames have no body
	}

	asdu := b[offASDU:]
	if len(asdu) < asduHeaderLen {
		return f, ErrBadLength
	}
	asduOff := baseOff + offASDU

	h := &ASDUHeader{
		TypeID:           asdu[0],
		SQ:               asdu[1]&0x80 != 0,
		NumObjects:       asdu[1] & 0x7f,
		Cause:            asdu[2] & 0x3f,
		Negative:         asdu[2]&0x40 != 0,
		Test:             asdu[2]&0x80 != 0,
		Originator:       asdu[3],
		OriginatorOffset: asduOff + 3,
		CommonAddr:       uint16(asdu[4]) | uint16(asdu[5])<<8,
		CommonAddrOffset: asduOff + 4,
	}

	if err := dissectObjects(asdu, asduOff, h); err != nil {
		return f, err
	}
	f.ASDU = h
	return f, nil
}

// Defines fixed byte size of a information elements for given ID
type objLayout struct {
	elemSize int
	hasTime  bool // Marks if object ends with CP56Time2a
}

var typeLayouts = map[uint8]objLayout{
	// Process information in monitor direction (no 7-byte timestamp)
	1:  {1, false}, // M_SP_NA_1: SIQ (1)
	2:  {4, false}, // M_SP_TA_1: SIQ (1) + CP24Time2a (3)
	3:  {1, false}, // M_DP_NA_1: DIQ (1)
	4:  {4, false}, // M_DP_TA_1: DIQ (1) + CP24Time2a (3)
	5:  {2, false}, // M_ST_NA_1: VTI (1) + QDS (1)
	6:  {5, false}, // M_ST_TA_1: VTI (1) + QDS (1) + CP24Time2a (3)
	7:  {5, false}, // M_BO_NA_1: BSI (4) + QDS (1)
	8:  {8, false}, // M_BO_TA_1: BSI (4) + QDS (1) + CP24Time2a (3)
	9:  {3, false}, // M_ME_NA_1: NVA (2) + QDS (1)
	10: {6, false}, // M_ME_TA_1: NVA (2) + QDS (1) + CP24Time2a (3)
	11: {3, false}, // M_ME_NB_1: SVA (2) + QDS (1)
	12: {6, false}, // M_ME_TB_1: SVA (2) + QDS (1) + CP24Time2a (3)
	13: {5, false}, // M_ME_NC_1: IEEE754 (4) + QDS (1)
	14: {8, false}, // M_ME_TC_1: IEEE754 (4) + QDS (1) + CP24Time2a (3)
	15: {5, false}, // M_IT_NA_1: BCR (5)
	16: {8, false}, // M_IT_TA_1: BCR (5) + CP24Time2a (3)
	17: {6, false}, // M_EP_TA_1: SEP (1) + CP16Time2a (2) + CP24Time2a (3)
	18: {7, false}, // M_EP_TB_1: SEP (1) + QDP (1) + CP16Time2a (2) + CP24Time2a (3)
	19: {7, false}, // M_EP_TC_1: OCI (1) + QDP (1) + CP16Time2a (2) + CP24Time2a (3)
	20: {5, false}, // M_PS_NA_1: SCD (4) + QDS (1)
	21: {2, false}, // M_ME_ND_1: NVA (2)

	// Process telegrams with long time tag (CP56Time2a)
	30: {1, true}, // M_SP_TB_1: SIQ (1) + CP56Time2a
	31: {1, true}, // M_DP_TB_1: DIQ (1) + CP56Time2a
	32: {2, true}, // M_ST_TB_1: VTI (1) + QDS (1) + CP56Time2a
	33: {5, true}, // M_BO_TB_1: BSI (4) + QDS (1) + CP56Time2a
	34: {3, true}, // M_ME_TD_1: NVA (2) + QDS (1) + CP56Time2a
	35: {3, true}, // M_ME_TE_1: SVA (2) + QDS (1) + CP56Time2a
	36: {5, true}, // M_ME_TF_1: IEEE754 (4) + QDS (1) + CP56Time2a
	37: {5, true}, // M_IT_TB_1: BCR (5) + CP56Time2a
	38: {3, true}, // M_EP_TD_1: SEP (1) + CP16Time2a (2) + CP56Time2a
	39: {4, true}, // M_EP_TE_1: SEP (1) + QDP (1) + CP16Time2a (2) + CP56Time2a
	40: {4, true}, // M_EP_TF_1: OCI (1) + QDP (1) + CP16Time2a (2) + CP56Time2a

	// Process information in control direction
	45: {1, false}, // C_SC_NA_1: SCO (1)
	46: {1, false}, // C_DC_NA_1: DCO (1)
	47: {1, false}, // C_RC_NA_1: RCO (1)
	48: {3, false}, // C_SE_NA_1: NVA (2) + QOS (1)
	49: {3, false}, // C_SE_NB_1: SVA (2) + QOS (1)
	50: {5, false}, // C_SE_NC_1: IEEE754 (4) + QOS (1)
	51: {4, false}, // C_BO_NA_1: BSI (4)

	// Command telegrams with long time tag (CP56Time2a)
	58: {1, true}, // C_SC_TA_1: SCO (1) + CP56Time2a
	59: {1, true}, // C_DC_TA_1: DCO (1) + CP56Time2a
	60: {1, true}, // C_RC_TA_1: RCO (1) + CP56Time2a
	61: {3, true}, // C_SE_TA_1: NVA (2) + QOS (1) + CP56Time2a
	62: {3, true}, // C_SE_TB_1: SVA (2) + QOS (1) + CP56Time2a
	63: {5, true}, // C_SE_TC_1: IEEE754 (4) + QOS (1) + CP56Time2a
	64: {4, true}, // C_BO_TA_1: BSI (4) + CP56Time2a

	// System information (monitor & control)
	70:  {1, false}, // M_EI_NA_1: COI (1)
	100: {1, false}, // C_IC_NA_1: QOI (1)
	101: {1, false}, // C_CI_NA_1: QCC (1)
	102: {0, false}, // C_RD_NA_1: null (0)
	103: {0, true},  // C_CS_NA_1: CP56Time2a
	104: {2, false}, // C_TS_NB_1: FBP (2)
	105: {1, false}, // C_RP_NC_1: QRP (1)
	106: {2, false}, // C_CD_NA_1: CP16Time2a (2)
	107: {2, true},  // C_TS_TA_1: TSC (2) + CP56Time2a

	// Parameter in control direction
	110: {3, false}, // P_ME_NA_1: NVA (2) + QPM (1)
	111: {3, false}, // P_ME_NB_1: SVA (2) + QPM (1)
	112: {5, false}, // P_ME_NC_1: IEEE754 (4) + QPM (1)
	113: {1, false}, // P_AC_NA_1: QPA (1)

	// File transfer (fixed-length types)
	120: {6, false}, // F_FR_NA_1: NOF (2) + LOF (3) + FRQ (1)
	121: {7, false}, // F_SR_NA_1: NOF (2) + NOS (1) + LOF (3) + SRQ (1)
	122: {4, false}, // F_SC_NA_1: NOF (2) + NOS (1) + SCQ (1)
	123: {5, false}, // F_LS_NA_1: NOF (2) + NOS (1) + LSQ (1) + CHS (1)
	124: {4, false}, // F_AF_NA_1: NOF (2) + NOS (1) + AFQ (1)
	126: {6, true},  // F_DR_TA_1: NOF (2) + LOF (3) + SOF (1) + CP56Time2a
}

// Walks the information objects and records IOA and CP56Time2a byte offsets
func dissectObjects(asdu []byte, asduOff int, h *ASDUHeader) error {
	if h.NumObjects == 0 {
		return nil
	}
	spec, ok := typeLayouts[h.TypeID]
	if !ok {
		// Unknown type extract only IOA
		if len(asdu) >= 9 {
			h.Objects = append(h.Objects, InfoObject{
				IOA:        uint32(asdu[6]) | uint32(asdu[7])<<8 | uint32(asdu[8])<<16,
				IOAOffset:  asduOff + 6,
				TimeOffset: -1,
			})
		}
		return nil
	}

	pos := asduHeaderLen
	for i := 0; i < int(h.NumObjects); i++ {
		obj := InfoObject{IOAOffset: -1, TimeOffset: -1}

		// SQ = false, each object carries its own IOA
		// SQ = true, only object 0 carries the base IOA, others are IOA + n
		if !h.SQ || i == 0 {
			if pos+3 > len(asdu) {
				return ErrBadLength
			}
			obj.IOA = uint32(asdu[pos]) | uint32(asdu[pos+1])<<8 | uint32(asdu[pos+2])<<16
			obj.IOAOffset = asduOff + pos
			pos += 3
		}

		// Move past data bytes
		if pos+spec.elemSize > len(asdu) {
			return ErrBadLength
		}
		pos += spec.elemSize

		// Record timestamp offset
		if spec.hasTime {
			if pos+7 > len(asdu) {
				return ErrBadLength
			}
			obj.TimeOffset = asduOff + pos
			pos += 7
		}

		h.Objects = append(h.Objects, obj)
	}
	return nil
}
