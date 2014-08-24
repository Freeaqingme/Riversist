// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This binary provides sample code for using the gopacket TCP assembler and TCP
// stream reader.  It reads packets off the wire and reconstructs HTTP requests
// it sees, logging them.
package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"runtime"
	"time"
)

var processedIps map[string]int64

func main() {

	processedIps = make(map[string]int64)

	ticker := time.NewTicker(time.Second * 10)
	go func() {
		for _ = range ticker.C {
			fmt.Println(time.Now(), "Checking if any ip's should be cleaned from processedIps")
			fmt.Println("ProcessedIps contains", len(processedIps), "IP's")

			cleanThreshold := time.Now().Unix() - 10

			for k, v := range processedIps {
				if v < cleanThreshold {
					delete(processedIps, k)
				}
			}
			fmt.Println("ProcessedIps contains", len(processedIps), "IP's")

		}
	}()

	if handle, err := pcap.OpenLive("eth0", 128, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and ip and (port 80 or port 443 or port 21 or port 20)"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			p := packet
			if net := p.NetworkLayer(); net == nil {
				fmt.Println("No net layer found")
			} else {
				ip4 := net.(*layers.IPv4)
				tcp := p.TransportLayer().(*layers.TCP)
				fmt.Println(ip4.SrcIP.String(), tcp.SrcPort, "->", ip4.DstIP.String(), tcp.DstPort)

				srcIp := ip4.SrcIP.String()
				dstIp := ip4.SrcIP.String()
				curTime := time.Now().Unix()

				if _, ok := processedIps[srcIp]; ok {
					fmt.Println(srcIp, "is already in processedIps")
				} else {
					processedIps[ip4.SrcIP.String()] = curTime
				}

				if _, ok := processedIps[dstIp]; ok {
					fmt.Println(dstIp, "is already in destinationIps")
				} else {
					processedIps[dstIp] = curTime
				}

				//fmt.Println(processedIps)

				_ = &runtime.MemStats{}
				//            memStats := &runtime.MemStats{}
				//            runtime.ReadMemStats(memStats)
				//            fmt.Println("Length:", len(processedIps), runtime.NumGoroutine(), memStats.Alloc, memStats.TotalAlloc)
			}
		}
	}

}
