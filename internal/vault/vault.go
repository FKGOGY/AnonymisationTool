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
	seed       []byte
	timeOffset time.Duration
	cpan       *cryptopan.Cryptopan
	ipMap      map[string]net.IP
	macMap     map[string]net.HardwareAddr
	strMap     map[string]string // Just placeholder, will have separate maps probably
}

func NewVault(seed []byte) (*Vault, error) {
	// Crypto-PAn initialization, it needs 32 bit key
	h := hmac.New(sha256.New, seed)
	h.Write([]byte("crypto-pan"))

	cpan, err := cryptopan.New(h.Sum(nil))
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		seed:       seed,
		timeOffset: 300 * 24 * time.Hour, // Change the value later, just for testing
		cpan:       cpan,
		ipMap:      make(map[string]net.IP),
		macMap:     make(map[string]net.HardwareAddr),
		strMap:     make(map[string]string),
	}

	return vault, nil
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
		bytes.HasPrefix(mac, macPrefixIPv4Multicast) ||
		bytes.HasPrefix(mac, macPrefixIPv6Multicast) ||
		bytes.HasPrefix(mac, macPrefixGOOSE)
}

func (v *Vault) MapMAC(mac net.HardwareAddr) net.HardwareAddr {
	// Check existing mapping
	key := mac.String()
	existing, ok := v.macMap[key]
	if ok {
		return existing
	}

	// Check special value
	// TODO Multicast MAC is based on IP address so i should change it based on IP
	// Could check if its MULTICAST right away and then later in IP just look and remap if necesary
	if isSpecialMac(mac) {
		return mac
	}

	h := hmac.New(sha256.New, v.seed) // Create hasher
	h.Write(mac[:3])                  // Feed it OUI
	sum := h.Sum(nil)                 // Create

	out := make(net.HardwareAddr, 6)
	copy(out[:3], sum[:3]) // 24 bits from HMAC
	copy(out[3:], mac[3:]) // NIC without change

	out[0] = (out[0] &^ 0x03) | // Clear both
		0x02 | // Set U/L = 1
		(mac[0] & 0x01) // Set I/G = previous

	v.macMap[key] = out
	return out
}

// TODO
func (v *Vault) remapMulticastMAC(mac net.HardwareAddr) net.HardwareAddr {
	return mac
}

func (v *Vault) ShiftTime(t time.Time) time.Time {
	return t.Add(v.timeOffset)
}
