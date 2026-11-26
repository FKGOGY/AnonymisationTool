// /internal/protocols/handler.go
package protocols

import (
	"github.com/AnonymisationTool/internal/vault"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Handler interface {
	Name() string
	Match(pkt gopacket.Packet) bool
	Anonymize(payload []byte, v *vault.Vault) ([]byte, error)
}

// Checks if any protocol handler matches given packet
func Detect(handlers []Handler, pkt gopacket.Packet) Handler {
	for _, h := range handlers {
		if h.Match(pkt) {
			return h
		}
	}
	return nil
}

// Checks if packet is TCP with the given port as eiither src or dst
func TCPPort(pkt gopacket.Packet, port uint16) bool {
	tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return ok && (uint16(tcp.SrcPort) == port || uint16(tcp.DstPort) == port)
}

// Checks if packet is UDP with the given port as eiither src or dst
func UDPPort(pkt gopacket.Packet, port uint16) bool {
	udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return ok && (uint16(udp.SrcPort) == port || uint16(udp.DstPort) == port)
}
