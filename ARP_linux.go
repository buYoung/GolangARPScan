package Global

import (
	"errors"
	"fmt"
	"log"
	"time"
	"net"
	"github.com/google/gopacket/pcap"
)

func (i *Ipinfo) Init() (err error) {
	defer func() {
		s := recover()
		if s != nil {
			err = errors.New(fmt.Sprintf("%v", s))
		}
	}()
	log.Println("Run linux")
	i.checkoldConnection()
	conn, err := net.Dial("udp", "192.168.1.1:80") // 사용된 ip는 localhost // loopback 을 제외한 아이피 모두 사용가능 (단, 반환 안되는 아이피는 사용불가능)
	if err != nil {
		log.Println("Cannot get IP", err)
	}
	i.Ip = conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()
	interfacesnet, _ := net.Interfaces()
	for _, v := range interfacesnet {
		addrs, _ := v.Addrs()
		find := false
		for _, j := range addrs {
			ip, ipnet, _ := net.ParseCIDR(j.String())
			if ip.Equal(i.Ip) {
				i.Mask = ipnet.Mask
				i.Mac = v.HardwareAddr
				i.Devicename = v.Name
				find = true
				break
			}
		}
		if find {
			break
		}
	}
	i.Handle, err = pcap.OpenLive(i.Devicename, 65535, false, -1*time.Second)
	if err != nil {
		log.Fatal("OpenLive Call: ", err)
	}
	return

}
