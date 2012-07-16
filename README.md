HTTP Replay
===========
This project listens on TCP port 5665 for a streamed pcap file containing HTTP requests.  It 
minimally tries to build the packets into a request and then forwards them localhost:8081.

Expect lots of bad HTTP requests because requests that are split over multiple packets will 
be truncated unless the packets come in-order.  This worked well enough for my testing needs.

## Dependencies
### gopcap
	Install libpcap (tcpdump)
    go get github.com/akrennmair/gopcap

### Capture
    on linux as root to capture port 80:
    tcpdump -s 0 -w - -ieth0 "dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)" | tee live_dump.pcap | nc myhost 5665
    
The tcpdump filter above discards non-data packets. The tee command writes the pcap data to a file
and may be omitted.  The nc command forwards the pcap data over the network to the host running
httpreplay.

### Replay pcap file
	nc myhost 5665 < live_dump.pcap
	
