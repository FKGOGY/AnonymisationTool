// /internal/vault/vault.go
// Vault stores anonymization mappings and offsets of identifiers
package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"time"

	"github.com/Yawning/cryptopan"
)

type Vault struct {
	seed   [32]byte
	cpan   *cryptopan.Cryptopan
	ipMap  map[string]net.IP
	macMap map[string]net.HardwareAddr
	strMap map[string]string // Just placeholder, will have separate maps probably

	// IEC 104
	dayShift int
	location *time.Location
	iec104   *IEC104State
}

func NewVault(seed [32]byte, dayShift int, location *time.Location) (*Vault, error) {
	if location == nil {
		location = time.UTC
	}

	// Crypto-PAn initialization, it needs 32 bit key
	h := hmac.New(sha256.New, seed[:])
	h.Write([]byte("crypto-pan"))

	cpan, err := cryptopan.New(h.Sum(nil))
	if err != nil {
		return nil, err
	}

	iec104State, err := NewIEC104State(seed)
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		seed:     seed,
		cpan:     cpan,
		ipMap:    make(map[string]net.IP),
		macMap:   make(map[string]net.HardwareAddr),
		strMap:   make(map[string]string),
		dayShift: dayShift,
		location: location,
		iec104:   iec104State,
	}

	return vault, nil
}

func (v *Vault) IEC104() *IEC104State {
	return v.iec104
}

func (v *Vault) DayShift() int {
	return v.dayShift

}
func (v *Vault) Location() *time.Location {
	return v.location
}

// IPv4 Mapping
var preservedIPv4Nets = mustParseCIDRs(
	"0.0.0.0/8",      // Unspecified
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // APIPA
	"224.0.0.0/4",    // class D
	"240.0.0.0/4",    // class E
)

// Parses specified CIDRs into array
func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		nets = append(nets, net)
	}
	return nets
}

func isPreservedIPv4(ip net.IP) bool {
	for _, n := range preservedIPv4Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *Vault) MapIP(ip net.IP) net.IP {
	// Check if its IPv4
	ip4 := ip.To4()
	if ip4 == nil {
		return ip // IPv6 is not handled
	}

	// Check existing
	key := ip4.String()
	if existing, ok := v.ipMap[key]; ok {
		return existing
	}

	// Check preserved ones
	if isPreservedIPv4(ip4) {
		return ip
	}

	// Anonymize
	out := v.cpan.Anonymize(ip4)
	if o4 := out.To4(); o4 != nil {
		out = o4
	}

	v.ipMap[key] = out
	return out
}

// Mac Mapping
var (
	macBroadcast           = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	macPrefixIPv4Multicast = []byte{0x01, 0x00, 0x5E}       // 01::00:5E:xx:xx:xx
	macPrefixIPv6Multicast = []byte{0x33, 0x33}             // 33:33:xx:xx:xx:xx
	macPrefixGOOSE         = []byte{0x01, 0x0C, 0xCD, 0x01} // 01:0C:CD:01:xx:xx
)

func isSpecialMac(mac net.HardwareAddr) bool {
	return bytes.Equal(mac, macBroadcast) ||
		bytes.HasPrefix(mac, macPrefixIPv6Multicast) ||
		bytes.HasPrefix(mac, macPrefixGOOSE)
}

func isMulticastIPv4(mac net.HardwareAddr) bool {
	return bytes.HasPrefix(mac, macPrefixIPv4Multicast)
}

func (v *Vault) MapMAC(mac net.HardwareAddr) (net.HardwareAddr, bool) {
	// Check existing mapping
	key := mac.String()
	existing, ok := v.macMap[key]
	if ok {
		return existing, false
	}

	// Check IPv4 multicast, should be changed base on IPv4 address later
	if isMulticastIPv4(mac) {
		return mac, true
	}

	// Check special value
	if isSpecialMac(mac) {
		return mac, false
	}

	h := hmac.New(sha256.New, v.seed[:]) // Create hasher
	h.Write(mac[:3])                     // Feed it OUI
	sum := h.Sum(nil)                    // Create

	out := make(net.HardwareAddr, 6)
	copy(out[:3], sum[:3]) // 24 bits from HMAC
	copy(out[3:], mac[3:]) // NIC without change

	out[0] = (out[0] &^ 0x03) | // Clear both
		0x02 | // Set U/L = 1
		(mac[0] & 0x01) // Set I/G = previous

	v.macMap[key] = out
	return out, false
}

// Creates new multicast mac address based on the IPv4
func (v *Vault) RemapMulticastMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	return net.HardwareAddr{0x01, 0x00, 0x5E, ip4[1] & 0x7F, ip4[2], ip4[3]}
}

// Shift by whole days
func (v *Vault) ShiftTime(t time.Time) time.Time {
	return t.In(v.location).AddDate(0, 0, v.dayShift).UTC()
}
