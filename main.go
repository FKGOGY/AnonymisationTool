package main

import (
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	macMap  = map[string]net.HardwareAddr{}
	ipMap   = map[string]net.IP{}
	usedMAC = map[string]bool{}
	usedIP  = map[string]bool{}
	rng     = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// Multicast/broadcast MACs are left alone
func mapMAC(mac net.HardwareAddr) net.HardwareAddr {
	if len(mac) != 6 || mac[0]&1 == 1 {
		return mac
	}
	key := mac.String()
	if n, ok := macMap[key]; ok {
		return n
	}
	for {
		n := make(net.HardwareAddr, 6)
		rng.Read(n)
		n[0] = (n[0] &^ 1) | 2 // unicast, locally administered
		if !usedMAC[n.String()] {
			usedMAC[n.String()] = true
			macMap[key] = n
			return n
		}
	}
}

func mapIP(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil || ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ip.IsUnspecified() {
		return ip
	}
	key := ip.String()
	if n, ok := ipMap[key]; ok {
		return n
	}
	for {
		n := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254))).To4()
		if !usedIP[n.String()] {
			usedIP[n.String()] = true
			ipMap[key] = n
			return n
		}
	}
}

func main() {
	in, err := os.Open("iec104.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	defer in.Close()

	r, err := pcapgo.NewNgReader(in, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		log.Fatal(err)
	}

	out, err := os.Create("iec104_edited.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	w := pcapgo.NewWriter(out)
	if err := w.WriteFileHeader(65535, r.LinkType()); err != nil {
		log.Fatal(err)
	}

	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break // EOF
		}

		newData, ok := rewrite(data, r.LinkType())
		if !ok {
			continue
		}

		ci.CaptureLength = len(newData)
		ci.Length = len(newData)
		if err := w.WritePacket(ci, newData); err != nil {
			log.Fatal(err)
		}
	}

	for o, n := range macMap {
		log.Printf("MAC %s -> %s", o, n)
	}
	for o, n := range ipMap {
		log.Printf("IP  %s -> %s", o, n)
	}
}

func rewrite(data []byte, lt layers.LinkType) ([]byte, bool) {
	packet := gopacket.NewPacket(data, lt, gopacket.Default)

	eth, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if eth == nil || ip == nil || tcp == nil {
		return nil, false // not Ethernet/IPv4/TCP
	}

	eth.SrcMAC = mapMAC(eth.SrcMAC)
	eth.DstMAC = mapMAC(eth.DstMAC)
	ip.SrcIP = mapIP(ip.SrcIP)
	ip.DstIP = mapIP(ip.DstIP)
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(tcp.Payload)); err != nil {
		log.Printf("serialize failed, keeping original: %v", err)
		return nil, false
	}
	return buf.Bytes(), true
}
