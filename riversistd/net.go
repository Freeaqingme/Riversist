package riversistd

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"net"
)

func server(loop chan error) {
	handle, err := pcap.OpenLive(Config.Riversist.Interface, 128, true, 0)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter(Config.Riversist.Libpcap_Filter); err != nil { // optional
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		loop <- nil

		p := packet
		net := p.NetworkLayer()
		if net == nil {
			logger.Log(LOG_WARNING, "No net layer in packet found")
			continue
		}
		ip4 := net.(*layers.IPv4)
		tcp := p.TransportLayer().(*layers.TCP)
		srcIp := ip4.SrcIP.String()
		dstIp := ip4.DstIP.String()
		logger.Log(LOG_DEBUG, fmt.Sprintf("Received packet from %s:%s to %s:%s", srcIp, tcp.SrcPort, dstIp, tcp.DstPort))

		go processIp(srcIp)
		go processIp(dstIp)

		//		_ = &runtime.MemStats{}
		//            memStats := &runtime.MemStats{}
		//            runtime.ReadMemStats(memStats)
		//            fmt.Println("Length:", len(processedIps), runtime.NumGoroutine(), memStats.Alloc, memStats.TotalAlloc)
	}

}

func setOwnIps() {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Fatal(fmt.Sprintf("Could not determine own IP's: %v", err))
	}

	ownIps.Lock()
	defer ownIps.Unlock()

	if len(ownIps.m) > 0 {
		logger.Log(LOG_NOTICE, "Clearing ownIps table")
		for k := range ownIps.m {
			delete(ownIps.m, k)
		}
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			logger.Fatal(fmt.Sprintf("Could not determine own IP's: %v", err))
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				ip4 := ipnet.IP.To4()
				if ip4 == nil {
					continue
				}
				ownIps.m[ip4.String()] = 1337
				logger.Log(LOG_INFO, fmt.Sprintf("Added %s to ownIps map", ip4))
			}
		}
	}

}
