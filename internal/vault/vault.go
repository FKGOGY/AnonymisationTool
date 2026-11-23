// /internal/vault/vault.go
// Vault stores anonymization mappings and offsets of identifiers
package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"time"
)

type Vault struct {
	seed       []byte
	timeOffset time.Duration
	ipMap      map[string]net.IP
	macMap     map[string]net.HardwareAddr
	strMap     map[string]string // Just placeholder, will have separate maps probably
}

func NewVault(seed []byte) *Vault {
	vault := &Vault{
		seed:       seed,
		timeOffset: 300 * 24 * time.Hour, // Change the value later, just for testing
		ipMap:      make(map[string]net.IP),
		macMap:     make(map[string]net.HardwareAddr),
		strMap:     make(map[string]string),
	}

	return vault
}

// Not implemented!
func (v *Vault) MapIP(ip net.IP) net.IP {
	return ip
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
	existing, ok := v.macMap[mac.String()]
	if ok {
		return existing
	}

	// Check special value
	// TODO Multicast MAC is based on IP address so i should change it based on IP
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

	v.macMap[mac.String()] = out
	return out
}

func (v *Vault) ShiftTime(t time.Time) time.Time {
	return t.Add(v.timeOffset)
}
