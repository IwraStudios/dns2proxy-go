package main

import (
	"fmt"
	"net"
	"syscall"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"C"
	"os/exec"
)

//import "./pcap-master/pcap"

var consultas [10]net.IP
var spoof [10]net.IP
var dominios [10]net.IP
var transformation [10]net.IP
var nospoof [10]net.IP
var nospoofto [10]net.IP
var victims [10]net.IP

var logreqfile = "dnslog.txt"
var logsnifffile = "snifflog.txt"
var logalertfile = "dnsalert.txt"
var resolveconf = "resolv.conf"
var victimfile = "victims.cfg"
var nospooffile = "nospoof.cfg"
var nospooftofile = "nospoofto.cfg"
var specificfile = "spoof.cfg"
var dominiosfile = "domains.cfg"
var transformfile = "transform.cfg"
var fakeips [10]net.IP
var s []string
var sockad syscall.SockaddrInet4
var ip1 string= "None"
var adminip string = "192.168.0.1"
var noserv bool = false

func processfiles() {
	var a net.IP = []byte{74, 125, 136, 108} //Original Contents of nospooffile
	nospoof[0] = a

	//NOTE: skipping Some Files they were empty by default

	var b net.IP = []byte{127, 0, 0, 1} // Don't spoof self
	nospoofto[0] = b

}

func ThreadGo(){
	dev := GetActiveInterface() //TODO:Unreliable method change to Csploit input in the release (also for manual config)
	ca, err := pcap.OpenLive(dev,255,1,0)
	if err != nil {
		log.Fatal(err)
	}
	bpffilter := fmt.Sprintf("dst host %s and not src host %s and !(tcp dst port 80 or tcp dst port 443) and (not host %s)",ip1, ip1, adminip)
	ca.SetBPFFilter(bpffilter)
	defer ca.Close()

	packetSource := gopacket.NewPacketSource(ca, ca.LinkType())
	for true{
		pack, err := packetSource.NextPacket()
		if err != nil {
			log.Fatal(err)
		}else {
			ThreadParsePacket(pack)
		}


	}
}

func IPinArray(a net.IP, list []net.IP) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func ThreadParsePacket(pack gopacket.Packet){
	ipLayer := pack.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp := ipLayer.(*layers.TCP)
		prot := ip.Protocol
		version := ip.Version
		length := ip.Length
		dest_addr := ip.DstIP
		sourc_addr := ip.SrcIP
		sourc_port := tcp.SrcPort
		dest_port := tcp.DstPort
		if tcp != nil {
			//if IPinArray(sourc_addr, consultas){} //if consultas.has_key(str(s_addr))
			var cmdarg string
			cmdarg := fmt.Sprintf("-D INPUT -p tcp -d %s --dport %s -s %s --sport %s --j REJECT --reject-with tcp-reset", ip1, dest_port.String(), sourc_addr.String(), sourc_port.String())
			cmd := exec.Command("/sbin/iptables", cmdarg)
		}




	}

}

func GetLocalIPString() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "" //Might want to change that in the future
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}
func GetLocalIPbyte() [4]byte{
	var b [4]byte;
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return b //Might want to change that in the future
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				for i := 0; i < 4; i++ {
					b[i] = ipnet.IP[i]
				}
			}
		}
	}
	return b
}

func GetActiveInterface() string  {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "" //Might want to change that in the future
	}
	for addr, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return address.String()
			}
		}
	}
}

func main() {
	StartMain()
}

func DebugPrint(log string){
	PrintLn(log)
}

func StartMain(){
	processfiles()
	println("hello")
	println(nospoof[0])
	//var sig = syscall.Signal()
	p, err:= syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		log.Fatal(err)
	}
	syscall.SetsockoptInt(p,syscall.SOL_SOCKET, syscall.SO_REUSEADDR,1)
	sockad.Addr = GetLocalIPbyte()
	sockad.Port = 53 //port in python version
	syscall.Bind(p, &sockad) // Give Current IP

	for true {
		msg,address,err:= syscall.Recvfrom(p,1024,0)
		if err != nil {
			log.Fatal(err)
		} else {
			noserv = true
		}
		if noserv{
			//TODO:SAVE
		}
	}

}
