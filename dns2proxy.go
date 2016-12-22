package main

import (
	"C"
	"fmt"
	"github.com/google/gopacket" //using google's gopacket library
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"strings"
	"log"
	"net"
	"os/exec"
	"syscall"
	"container/list"
	"encoding/binary"
	"strconv"
	"errors"
)

var consultas list.List
var spoof list.List
var dominios list.List
var transformation list.List
var nospoof list.List
var nospoofto list.List
var victims list.List

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
var ip1 string = ""
var ip2 string = ""
var adminip string = "192.168.0.1"
var noserv bool = false
var serv_ids list.List

type Debug struct {}
type Utils struct {}
var util = Utils{}
var debug = Debug{}

func processfiles() {
	//TODO: Clear lists
	util.ClearList(&nospoof)
	util.ClearList(&nospoofto)
	util.ClearList(&victims)
	util.ClearList(&dominios)
	util.ClearList(&spoof)

	var a net.IP = []byte{74, 125, 136, 108} //Original Contents of nospooffile
	nospoof.PushBack(a)

	//NOTE: skipping Some Files they were empty by default

	var b net.IP = []byte{127, 0, 0, 1} // Don't spoof self
	nospoofto.PushBack(b)

}

func (Utils) ClearList(list *list.List)  {
	for e := list.Front(); e != nil; e = e.Next() {
		list.Remove(e);
	}

}

//// TCP/IP part

func ThreadGo() {
	dev := util.GetActiveInterface() //TODO:Unreliable method change to Csploit input in the release (also for manual config)
	ca, err := pcap.OpenLive(dev, 255, true, 0)
	if err != nil {
		log.Fatal(err)
	}
	bpffilter := fmt.Sprintf("dst host %s and not src host %s and !(tcp dst port 80 or tcp dst port 443) and (not host %s)", ip1, ip1, adminip)
	ca.SetBPFFilter(bpffilter)
	defer ca.Close()

	packetSource := gopacket.NewPacketSource(ca, ca.LinkType())
	for true {
		pack, err := packetSource.NextPacket()
		if err != nil {
			log.Fatal(err)
		} else {
			ThreadParsePacket(pack)
		}

	}
}

func (Utils)IPinArray(a net.IP, list []net.IP) bool {
	for _, b := range list {
		if b.Equal(a) {
			return true
		}
	}
	return false
}

func (Utils) InterfaceinArray(a interface{}, list list.List) bool {
	for e := list.Front(); e != nil; e = e.Next() {
		if(e.Value == a){
			return  true;
		}
	}
	return false
}

func (Utils)IntToByteArray(input uint32) []byte{
	ouput := make([]byte, 4)
	binary.LittleEndian.PutUint32(ouput, input)
	return  ouput
}

func ThreadParsePacket(pack gopacket.Packet) {
	ipLayer := pack.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		tcp := ipLayer.(*layers.TCP)
		/*prot := ip.Protocol
		version := ip.Version
		length := ip.Length
		dest_addr := ip.DstIP */
		sourc_addr := ip.SrcIP
		sourc_port := tcp.SrcPort
		dest_port := tcp.DstPort
		if tcp != nil {
			if util.InterfaceinArray(sourc_addr, consultas) {
				//if consultas.has_key(str(s_addr))
				var cmdarg string

				cmdarg = fmt.Sprintf("%s %s %s %s", ip2, dest_port.String(), sourc_addr.String(), dest_port.String())
				cmd := exec.Command("sh ./IPBouncer.sh", cmdarg)
				err := cmd.Run()
				debug.ErrorHandler(err)

				cmdarg = fmt.Sprintf("-D INPUT -p tcp -d %s --dport %s -s %s --sport %s --j REJECT --reject-with tcp-reset", ip1, dest_port.String(), sourc_addr.String(), sourc_port.String())
				cmd = exec.Command("/sbin/iptables", cmdarg)
				err = cmd.Run()
				debug.ErrorHandler(err)

				cmdarg = fmt.Sprintf("-A INPUT -p tcp -d %s --dport %s -s %s --sport %s --j REJECT --reject-with tcp-reset", ip1, dest_port.String(), sourc_addr.String(), sourc_port.String())
				cmd = exec.Command("/sbin/iptables", cmdarg)
				err = cmd.Run()
				debug.ErrorHandler(err)
			}
		}

	}

}

func (Utils)GetLocalIPString() string {
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
func (Utils)GetLocalIPbyte() [4]byte {
	var b [4]byte
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

func (Utils)GetActiveInterface() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "" //Might want to change that in the future
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return address.String()
			}
		}
	}
	return ""
}

func requestHandler(address syscall.Sockaddr, message int) {
	if util.InterfaceinArray(message, serv_ids) {
		return
		//Already in progress
	}
	serv_ids.PushBack(message) //Change
	//TODO:SAVE

}

//// DNS part
func PTR_qry(msg dns.Msg){
	que := msg.Question
	iparp := strings.Split(que[0].String(),	" ")[0]
	debug.DebugPrint(strconv.Itoa(len(que))+ " questions.")
	debug.DebugPrint("Hosts" + iparp)
	//resp := make() //TODO: Make response function
}

func Make_Response(qry dns.Msg,id int, RCODE int) dns.Msg {
	resp := dns.Msg{}
	if qry.String() == resp.String() && id == 0{
		debug.ErrorHandler(errors.New("bad use of make_response"))
	}
	if qry.String() == resp.String() {
		resp.Id = uint16(id)
		resp.Response = true // QR = 1
		if(RCODE != 1){
			debug.DebugPrint("RCODE != 1	:241")
		}
	}else{
		resp.SetReply(&qry)
		resp.RecursionAvailable = true //RA
		resp.Authoritative = true //AA
		resp.SetRcode(&qry, RCODE)
	}
	return  resp
}

//// Main Part

func main() {
	StartMain()
}

func (Debug)DebugPrint(log string) {
	println(log)
}
func (Debug)ErrorHandler(err error) {
	if err != nil {
		log.Fatal(err)
	}

}


func StartMain() {
	processfiles()
	println("hello")
	println(nospoof.Front())
	//var sig = syscall.Signal()

	p, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0) //TODO: replace with high-level version (if possible)
	if err != nil {
		log.Fatal(err)
	}
	syscall.SetsockoptInt(p, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	sockad.Addr = util.GetLocalIPbyte()
	sockad.Port = 53         //port in python version
	syscall.Bind(p, &sockad) // Give Current IP

	for true {
		msg, address, err := syscall.Recvfrom(p, util.IntToByteArray(1024), 0) // TODO: byte-array-type of 1024??
		if err != nil {
			log.Fatal(err)
		} else {
			noserv = true
		}
		if noserv {

			requestHandler(address, msg)
		}
	}

}
