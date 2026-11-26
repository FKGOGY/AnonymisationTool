package goose

import (
	"fmt"

	"github.com/AnonymisationTool/internal/vault"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Handler struct{}

func (Handler) Name() string { return "goose" }

func (Handler) Match(pkt gopacket.Packet) bool {
	if dot1q, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok && dot1q.Type == EtherTypeGOOSE {
		return true
	}

	if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok && eth.EthernetType == EtherTypeGOOSE {
		return true
	}

	return false
}

func (Handler) Anonymize(payload []byte, v *vault.Vault) ([]byte, error) {
	return nil, fmt.Errorf("Not implemented!\n")
}
