package ARP

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"log"
	"net"
	"time"
)

func (i *Ipinfo) Init() (err error) {
	defer func() {
		s := recover()
		if s != nil {
			err = errors.New(fmt.Sprintf("%v", s))
		}
	}()
	i.checkoldConnection()
	conn, err := net.Dial("udp", "8.8.8.8:80") // 사용자의 인터넷 통신이 가능한 ip 추척 사용된 아이피는 loopback // localhost(127.0.0.1) 이외의 ip 사용가능
	if err != nil {
		log.Println("Cannot get IP", err)
	}
	i.Ip = conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("get interface", err)
	}
	for _, v := range interfaces {
		find := false
		for _, j := range v.Addresses {
			if j.IP.Equal(i.Ip) {
				find = true
				i.Devicename = v.Name
				i.Mask = j.Netmask
				break
			}
		}
		if find {
			break
		}
	}
	interfacesnet, _ := net.Interfaces()
	for _, v := range interfacesnet {
		ipdd, _ := v.Addrs()
		find := false

		for _, h := range ipdd {
			ipd, _, _ := net.ParseCIDR(h.String())
			if ipd.Equal(i.Ip) {
				find = true
				i.Mac = v.HardwareAddr
				break
			}
		}
		if find {
			break
		}
	}

	i.Handle, err = pcap.OpenLive(i.Devicename, 65535, false, -1*time.Second)
	if err != nil {
		log.Println("OpenLive Call: ", err)
	}

	return
}
