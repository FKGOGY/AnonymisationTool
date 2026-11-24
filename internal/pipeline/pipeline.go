// /internal/pipeline/pipeline.go
// Pipeline reads a capture, decides which protocol each packet carries and dissects it
package pipeline

import (
	"fmt"
	"io"
	"os"

	"github.com/AnonymisationTool/internal/pcapio"
	"github.com/AnonymisationTool/internal/protocols"
	"github.com/AnonymisationTool/internal/protocols/iec104"
	"github.com/AnonymisationTool/internal/vault"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Run(inPath, outPath string, v *vault.Vault) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	src, err := pcapio.Open(inFile)
	if err != nil {
		return err
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	dst, err := pcapio.Create(outFile)
	if err != nil {
		return err
	}

	handlers := []protocols.Handler{
		iec104.Handler{},
		// Later add more handlers
	}

	for n := 1; ; n++ {
		data, ci, err := src.ReadPacketData()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading packet %d: %w", n, err)
		}
		if lt := src.LinkType(); lt != layers.LinkTypeEthernet {
			return fmt.Errorf("unsupported link type %v: only Ethernet is supported", lt)
		}

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		outBytes, err := rewritePacket(pkt, handlers, v)
		if err != nil {
			return fmt.Errorf("packet %d: %w", n, err)
		}
		if outBytes == nil {
			continue // Skip packets outside IEC 104, GOOSE, MMS and DLMS
		}

		ci.Timestamp = v.ShiftTime(ci.Timestamp)
		ci.CaptureLength = len(outBytes)
		ci.Length = len(outBytes)

		if err := dst.WritePacket(ci, outBytes); err != nil {
			return fmt.Errorf("writing packet %d: %w", n, err)
		}
	}
}

// isTargetFlow keeps packets belonging to IEC 104, GOOSE, MMS, or DLMS,
// including empty TCP handshake/ACK control packets on those ports.
func isTargetFlow(pkt gopacket.Packet) bool {
	if dot1q, ok := pkt.Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q); ok && dot1q.Type == protocols.EtherTypeGOOSE {
		return true
	}
	if eth, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok && eth.EthernetType == protocols.EtherTypeGOOSE {
		return true
	}
	if protocols.TCPPort(pkt, iec104.Port) || protocols.TCPPort(pkt, 102) || protocols.TCPPort(pkt, 4059) {
		return true
	}
	if protocols.UDPPort(pkt, 4059) {
		return true
	}
	return false
}

func rewritePacket(pkt gopacket.Packet, handlers []protocols.Handler, v *vault.Vault) ([]byte, error) {
	if !isTargetFlow(pkt) {
		return nil, nil
	}

	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil
	}
	eth := ethLayer.(*layers.Ethernet)
	//
	var dstMulticast bool
	eth.SrcMAC, _ = v.MapMAC(eth.SrcMAC)
	eth.DstMAC, dstMulticast = v.MapMAC(eth.DstMAC)

	outLayers := []gopacket.SerializableLayer{eth}

	// Preserve 802.1Q VLAN tag if present
	var dot1q *layers.Dot1Q
	if vlanLayer := pkt.Layer(layers.LayerTypeDot1Q); vlanLayer != nil {
		dot1q = vlanLayer.(*layers.Dot1Q)
		outLayers = append(outLayers, dot1q)
	}

	// Layer 3: IPv4 or IPv6
	var netLayer gopacket.NetworkLayer
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip4 := ipLayer.(*layers.IPv4)
		ip4.SrcIP = v.MapIP(ip4.SrcIP)
		ip4.DstIP = v.MapIP(ip4.DstIP)
		// remap ips and if mac address was Multicast then change it so it coresponds
		if dstMulticast {
			eth.DstMAC = v.RemapMulticastMAC(ip4.DstIP)
		}
		netLayer = ip4
		outLayers = append(outLayers, ip4)
	} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6 := ip6Layer.(*layers.IPv6)
		ip6.SrcIP = v.MapIP(ip6.SrcIP)
		ip6.DstIP = v.MapIP(ip6.DstIP)
		netLayer = ip6
		outLayers = append(outLayers, ip6)
	}

	// Layer 4 and extract application payload
	var appPayload []byte
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if netLayer == nil {
			return nil, nil
		}
		tcp := tcpLayer.(*layers.TCP)
		tcp.SetNetworkLayerForChecksum(netLayer)
		appPayload = tcp.Payload
		outLayers = append(outLayers, tcp)
	} else if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if netLayer == nil {
			return nil, nil
		}
		udp := udpLayer.(*layers.UDP)
		udp.SetNetworkLayerForChecksum(netLayer)
		appPayload = udp.Payload
		outLayers = append(outLayers, udp)
	} else if dot1q != nil {
		appPayload = dot1q.Payload
	} else {
		appPayload = eth.Payload
	}

	// Layer 7
	if len(appPayload) > 0 {
		if h := protocols.Detect(handlers, pkt); h != nil {
			mutated, err := h.Anonymize(appPayload, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", h.Name(), err)
			}
			appPayload = mutated
		}
		outLayers = append(outLayers, gopacket.Payload(appPayload))
	}

	return serialize(outLayers)
}

func serialize(layersToWrite []gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToWrite...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
