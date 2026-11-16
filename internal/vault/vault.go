// /internal/vault/vault.go
// Vault stores anonymization mappings and offsets of identifiers
package vault

import (
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

func NewVault() *Vault {
	vault := &Vault{
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

// Not implemented!
func (v *Vault) MapMAC(mac net.HardwareAddr) net.HardwareAddr {
	return mac
}

func (v *Vault) ShiftTime(t time.Time) time.Time {
	return t.Add(v.timeOffset)
}
