package main

import (
	pcap "github.com/akrennmair/gopcap"
	"net"
	"log"
	"bufio"
	"bytes"
	"strconv"
)

func main() {
	// used to pass the packet data to the go routine responsible for forwarding it
	var packet_chan = make(chan []byte, 100)

	for i:=0; i < 10; i++ {
		go forwarder(packet_chan)
	}
	
	var laddr net.TCPAddr
	laddr.IP = net.IPv4(0,0,0,0)
	laddr.Port = 5665
	listener, err := net.ListenTCP("tcp", &laddr)
	if err != nil {
		log.Println("Can't listen, barf:", err)
		return
	}
	
	for {
		connection, err := listener.Accept()
		if err == nil {
			log.Println("Got Connection")
			// only accept a single connection
			handle(connection, packet_chan)
		} else {
			log.Println("Can't accept, barf:", err)	
		}
	}

}

func handle(incoming net.Conn, packet_chan chan []byte) {
	defer incoming.Close()
	buf := bufio.NewReaderSize(incoming, 8192)
	
	reader, err := pcap.NewReader(buf)
	if err != nil {
		log.Println("Pcap reader error:", err)
		return
	}

	//for i := 0; i < 10; i++ {
	split := false
	var request []byte
	for {
		pkt := reader.Next()
		if pkt == nil {
			log.Println("Nil packet! stopping")
			break
		}
		if pkt.Data != nil && len(pkt.Data) > 66 {
			//log.Println("Got packet", i)
			//log.Println("POST at: ", bytes.Index(pkt.Data, []byte("POST")) )
			split, request = checkSplit(split, request, pkt.Data[66:])
			if !split {
				packet_chan <- request
			}
		}
	}
}

func checkSplit(split bool, request []byte, newdata []byte) (issplit bool, fullrequest []byte) {
	issplit = false
	// check for and append split data if we're split
	if split {
		issplit = false
		if bytes.HasPrefix(newdata, []byte("GET")) || bytes.HasPrefix(newdata, []byte("POST")) || bytes.HasPrefix(newdata, []byte("PUT")) || bytes.HasPrefix(newdata, []byte("DELETE")) {
			fullrequest = newdata
		} else {
			fullrequest = append(request, newdata...)
		}
	} else {
		fullrequest = newdata
	}

	// set split if necessary
	if bytes.HasPrefix(fullrequest, []byte("POST")) || bytes.HasPrefix(fullrequest, []byte("PUT")) {
		if ind := bytes.Index(fullrequest, []byte("Content-Length: ")); ind > 0 {
			endind := bytes.Index(fullrequest[ind:], []byte("\r\n"))
			//log.Println("IND:",ind, "END:",endind)
			cl, err := strconv.Atoi(string(fullrequest[ind+16:ind+endind]))
			if err != nil {
				log.Println("doh", err)
			}
			//log.Println("CL:", string(fullrequest[ind:ind+endind]), cl)

			bs := bytes.Index(fullrequest, []byte("\r\n\r\n")) + 4
			//log.Println("Size:", len(fullrequest), "BS:", bs)
			if bs + cl > len(fullrequest) {
				issplit = true
			}
		}
	}
	
	return
}

func forwarder(packet_chan chan []byte) {
	for pkt := range packet_chan {		
		forwardIt(pkt)
	}
}

func forwardIt(data []byte) {
//	outgoing, err := net.Dial("tcp", "192.168.56.102:8081")
	outgoing, err := net.Dial("tcp", "localhost:8081")
	if err == nil {
		defer outgoing.Close()
		buf := bufio.NewWriterSize(outgoing, 8192)
		//log.Println("Sending:", string(data) )
		buf.Write(data)
		buf.Flush()
		// should I wait for a response? nah
	} else {
		log.Println("Can't conenct to upstream:", err)	
	}
}
