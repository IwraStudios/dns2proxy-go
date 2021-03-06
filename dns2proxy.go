package main

import (
	"C"
	"fmt"
	"github.com/google/gopacket" //using google's gopacket library
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"container/list"
	"net"
	"syscall"
	"log"
	"encoding/binary"
	"os/exec"
	"strings"
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

	//NOTE: skipping Some Files they were empty by default; TODO: Needs future implementation

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

func requestHandler(address net.Addr, message []byte) {
	if util.InterfaceinArray(message, serv_ids) {
		return
		//Already in progress
	}
	serv_ids.PushBack(message) //Change; Make unique id
	//debug.DebugPrint("Client IP:" + address)
	msg := dns.Msg{}
	err := msg.Unpack(message)
	qs := msg.Question
	resp := interface{}(nil)
	if err != nil{
		debug.DebugPrint("got ??")
		resp = Make_Response(msg, 0, 2)
		debug.DebugPrint("resp ="  ) //TODO:+ resp
		//s.seto(resp, addr)
		return;
	}
	op := msg.Opcode
	if op == 0{
		if len(qs) > 0{
			q := qs[0]
			debug.DebugPrint("Request:" + q.String())
			//TODO: Save question to log
			switch (q.Qtype) {
			case dns.TypeA:
				//TODO: std stuff
				break;
			case dns.TypePTR:

				break;
			case dns.TypeMX:

				break;
			case dns.TypeTXT:

				break;
			case dns.TypeAAAA:

				break;
			default:
				debug.ErrorHandler(errors.New("Not Impl"))
				return;
			}

		}else {
			debug.ErrorHandler(errors.New("Not Impl"))
			return;
		}
	}
	if resp != interface{}(nil) {

		//TODO: SendTo
	}
}

//// DNS part

func respuestas(name string, typ string) []string  { //Don't know exact output yet; suspect net.IP | net.IPv4
	var a []string
	//conn, err := net.LookupIP(name) //Not sure if Golang needs typ or something else
 return a
}

func PTR_qry(msg dns.Msg) dns.Msg{
	que := msg.Question
	iparp := strings.Split(que[0].String(),	" ")[0]
	debug.DebugPrint(strconv.Itoa(len(que))+ " questions.")
	debug.DebugPrint("Hosts" + iparp)
	resp := Make_Response(msg, 0, 0)
	hosts := respuestas(iparp[:len(iparp)-1], "PTR")
	//TODO: isinstance()
	for i := 0; i < len(hosts); i++{
		rr, err := dns.NewRR(iparp + "1000 IN PTR 10" + hosts[i])
		debug.ErrorHandler(err)
		resp.Answer[i] = rr //TODO: change to append type
		//TODO:Find PTR resolver
	}
	return dns.Msg{} //TODO: CHANGE
}

func MX_qry(msg dns.Msg) dns.Msg{
	que := msg.Question
	iparp := strings.Split(que[0].String(),	" ")[0]
	debug.DebugPrint(strconv.Itoa(len(que))+ " questions.")
	debug.DebugPrint("Hosts" + iparp)
	resp := Make_Response(msg, 0, 3)
	return resp
	//Disabled in Original
}

func TXT_qry(msg dns.Msg) dns.Msg{
	que := msg.Question
	iparp := strings.Split(que[0].String(),	" ")[0]
	debug.DebugPrint(strconv.Itoa(len(que))+ " questions.")
	debug.DebugPrint("Host: " + iparp)
	//resp := Make_Response(msg, 0, 0)
	host := iparp[:len(iparp)-1]
	punto := strings.Index(host,".")
	dominio := host[punto:]
	host = "."+host
	spfresponse := " "
	if util.InterfaceinArray(dominio, dominios) || util.InterfaceinArray(host, dominios){
		//ttl := 1
		debug.DebugPrint("Alert domain! (TXT) ID: " + host)
		//TODO: save_req
		if util.InterfaceinArray(host, dominios){
			spfresponse = "v=spf1 a:mail"+host+"/24 mx -all "
		}
		if(util.InterfaceinArray(dominio,dominios)){
			spfresponse = "v=spf1 a:mail"+dominio+"/24 mx -all "
		}
		debug.DebugPrint("Responding with SPF = " + spfresponse)
		//TODO:SAVE

	}
	return dns.Msg{} //TODO: CHANGE
}

//TODO: Defualt should be {null, null, 0} proposed {empty,0,0}
func Make_Response(qry dns.Msg,id int, RCODE int) dns.Msg {
	resp := dns.Msg{}
	if qry.String() == resp.String() && id == 0{
		debug.ErrorHandler(errors.New("bad use of make_response"))
	}
	if qry.String() == resp.String() {
		resp.Id = uint16(id)
		resp.Response = true // QR = 1
		if(RCODE != 1){
			debug.ErrorHandler(errors.New("RCODE !=1"))
		}
	}else{
		resp.SetReply(&qry)
	}
	resp.RecursionAvailable = true //RA
	resp.Authoritative = true //AA
	resp.SetRcode(&qry, RCODE)
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
		conn, err := net.ListenPacket("udp", ":53")
		debug.ErrorHandler(err)
		//msg, address, err := syscall.Recvfrom(p, util.IntToByteArray(1024), 0)
		//var buf [1024]byte
		buf := make([]byte, 1024)
		_, address, err := conn.ReadFrom(buf)

		if err != nil {
			log.Fatal(err)
		} else {
			noserv = true
		}
		if noserv {

			requestHandler(address, buf)
		}
	}

}
