package ARP

import( 
	  "net"
  	"sync"
    "github.com/google/gopacket/pcap"
)

type Ipinfo struct {
	Ip         net.IP
	Mask       net.IPMask
	Mac        net.HardwareAddr
	Devicename string
	stop       bool
	Handle     *pcap.Handle
	mutex      sync.Mutex
}
