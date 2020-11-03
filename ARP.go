package ARP

import (
	"bytes"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"sync"
	"time"
)

func (i *Ipinfo) ARPRead() {
	i.mutex = sync.Mutex{} // ARPinit에서 사용해도 무관
	packetSource := gopacket.NewPacketSource(i.Handle, i.Handle.LinkType())
	in := packetSource.Packets()
	for {
		var pkt gopacket.Packet
		if i.stop {
			break
		}
		select {
		case pkt = <-in:
			arplayer := pkt.Layer(layers.LayerTypeARP)
			if arplayer == nil {
				continue
			}
			arp := arplayer.(*layers.ARP)

			if arp.Operation != layers.ARPReply || bytes.Equal(i.Mac, arp.SourceHwAddress) {
				continue
			}
			log.Printf("GET ARP REPLY IP : %v MAC : %v, %#v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress),arp)
		default:
			time.Sleep(time.Millisecond * 500)
		}
	}
}


func (i *Ipinfo) ARPSend() {
	for {
		if i.stop {
			break
		}
		eth := layers.Ethernet{
			SrcMAC:       i.Mac,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte(i.Mac),
			SourceProtAddress: []byte(i.Ip),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		for _, ip := range ips(&net.IPNet{IP: i.Ip, Mask: i.Mask}) {
			arp.DstProtAddress = []byte(ip.To4())
			gopacket.SerializeLayers(buf, opts, &eth, &arp)
			if err := i.Handle.WritePacketData(buf.Bytes()); err != nil {
				log.Println("send", err)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func (i *Ipinfo) ARPClose() {
	i.stop = true
	i.Handle.Close()
}

func ips(n *net.IPNet) (out []net.IP) { // ip대역을얻기위해 
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask

	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}

