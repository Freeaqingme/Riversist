package main

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	//    "gcfg"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"riversist/log"
	"time"
	"unsafe"
)

type ipMap struct {
	sync.RWMutex
	m map[string]int64
}

var logger log.Logger
var processedIps ipMap
var processingIps ipMap
var ownIps ipMap

func main() {

	processedIps = ipMap{m: make(map[string]int64)}
	processingIps = ipMap{m: make(map[string]int64)}
	ownIps = ipMap{m: make(map[string]int64)}

	setProcessName("riversist")

	logLevel := flag.Int("loglevel", 5, "Syslog Loglevel (0-7, Emerg-Debug)")
	flag.Parse()

	logger = logger.New(*logLevel)
	logger.Log(log.LOG_NOTICE, "Starting...")
	defer logger.Log(log.LOG_CRIT, "Exiting...")

	go cleanProcessedIps()
	go cleanProcessingIps()
	setOwnIps()

	sig := make(chan bool)
	loop := make(chan error)

	go sigHandler(sig)
	go server(loop)

	for quit := false; !quit; {
		select {
		case quit = <-sig:
		case <-loop:
		}
	}

}

// We make sigHandler receive a channel on which we will report the value of var quit
func sigHandler(q chan bool) {
	var quit bool

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for signal := range c {
		logger.Log(log.LOG_NOTICE, "Received signal: "+signal.String())

		switch signal {
		case syscall.SIGINT, syscall.SIGTERM:
			quit = true
		case syscall.SIGHUP:
			quit = false
		}

		if quit {
			quit = false
			logger.Log(log.LOG_CRIT, "Terminating...")
			//              closeDb()
			//              closeLog()
			os.Exit(0)
		}
		// report the value of quit via the channel
		q <- quit
	}
}

func setProcessName(name string) error {
	argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
	argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len]

	paddedName := fmt.Sprintf("%-"+strconv.Itoa(len(argv0))+"s", name)
	if len(paddedName) > len(argv0) {
		panic("Cannot set proccess name that is longer than original argv[0]")
	}

	n := copy(argv0, paddedName)
	if n < len(argv0) {
		argv0[n] = 0
	}

	return nil
}

func setOwnIps() {
	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Fatal(fmt.Sprintf("Could not determine own IP's: %v", err))
	}

	ownIps.Lock()
	defer ownIps.Unlock()

	if len(ownIps.m) > 0 {
		logger.Log(log.LOG_NOTICE, "Clearing ownIps table")
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
				logger.Log(log.LOG_INFO, fmt.Sprintf("Added %s to ownIps map", ip4))
			}
		}
	}

}

func server(loop chan error) {

	handle, err := pcap.OpenLive("eth0", 128, true, 0)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter("tcp and ip and (port 80 or port 443 or port 21 or port 20)"); err != nil { // optional
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		loop <- nil

		p := packet
		net := p.NetworkLayer()
		if net == nil {
			logger.Log(log.LOG_WARNING, "No net layer in packet found")
			continue
		}
		ip4 := net.(*layers.IPv4)
		tcp := p.TransportLayer().(*layers.TCP)
		srcIp := ip4.SrcIP.String()
		dstIp := ip4.DstIP.String()
		logger.Log(log.LOG_DEBUG, fmt.Sprintf("Received packet from %s:%s to %s:%s", srcIp, tcp.SrcPort, dstIp, tcp.DstPort))

		go processIp(srcIp)
		go processIp(dstIp)

		_ = &runtime.MemStats{}
		//            memStats := &runtime.MemStats{}
		//            runtime.ReadMemStats(memStats)
		//            fmt.Println("Length:", len(processedIps), runtime.NumGoroutine(), memStats.Alloc, memStats.TotalAlloc)
	}

}

func processIp(ip string) {
	curTime := time.Now().Unix()

	ownIps.RLock()
	if _, ok := ownIps.m[ip]; ok {
		logger.Log(log.LOG_DEBUG, fmt.Sprintf("%v is in the ownIps map. Skipping", ip))
		ownIps.RUnlock()
		return
	}
	ownIps.RUnlock()

	processedIps.RLock()
	if _, ok := processedIps.m[ip]; ok {
		logger.Log(log.LOG_DEBUG, fmt.Sprintf("%v has already been evaluated. Skipping", ip))
		processedIps.RUnlock()
		return
	}
	processedIps.RUnlock()

	processingIps.RLock()
	if _, ok := processingIps.m[ip]; ok {
		logger.Log(log.LOG_DEBUG, fmt.Sprintf("%v is already being evaluated. Skipping", ip))
		processingIps.RUnlock()
		return
	}
	processingIps.RUnlock()

	processingIps.Lock()
	processingIps.m[ip] = curTime
	processingIps.Unlock()

	addIpToTable(ip)

	processedIps.Lock()
	processingIps.Lock()
	processedIps.m[ip] = curTime
	delete(processingIps.m, ip)
	processingIps.Unlock()
	processedIps.Unlock()
}

func addIpToTable(ip string) {
	var cmdStr string
	if isIpHam(ip) {
		logger.Log(log.LOG_NOTICE, fmt.Sprintf("Evaluated IP: %s, table: ham", ip))
		cmdStr = "/home/dolf/Projects/Go/addIpToTable ham %s"
	} else {
		logger.Log(log.LOG_NOTICE, fmt.Sprintf("Evaluted IP: %s, table: spam", ip))
		cmdStr = "/home/dolf/Projects/Go/addIpToTable spam %s"
	}

	cmdStr = fmt.Sprintf(cmdStr, ip)
	cmdArr := strings.Split(cmdStr, " ")
	cmd := exec.Command(cmdArr[0], cmdArr[1:len(cmdArr)]...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		logger.Log(log.LOG_ERR, "Could not execute "+cmdStr+": ", err.Error())
	}

}

func isIpHam(ip string) bool {
	_ = fmt.Sprintf("%v", ip)
	return true // Make sure we do not DDOS project honeypot first

	if strings.Index(ip, ".") < 0 {
		// As we don't support IPv6 yet, it is all considered HAM
		return true
	}

	split_ip := strings.Split(ip, ".")
	rev_ip := strings.Join([]string{split_ip[3], split_ip[2], split_ip[1], split_ip[0]}, ".")

	host, err := net.LookupHost(fmt.Sprintf("configureme.%v.dnsbl.httpbl.org", rev_ip))
	if len(host) == 0 {
		logger.Log(log.LOG_DEBUG, "Received no result from httpbl.org:", err.Error())
		return true
	}

	// Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
	ret_octets := strings.Split(host[0], ".")
	if len(ret_octets) != 4 || ret_octets[0] != "127" {
		logger.Log(log.LOG_INFO, "Invalid return value from httpbl.org:", string(host[0]))
		return true
	}

	stale_period, _ := strconv.Atoi(ret_octets[1])
	threat_score, _ := strconv.Atoi(ret_octets[2])
	score := (10 / stale_period) * threat_score

	// Prefer it to be at least 10 days stale with a score of <25
	if stale_period > 14 {
		logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: stale, stale_period:", strconv.Itoa(stale_period), ", stale_threshold: ", strconv.Itoa(14), " verdict: ham, dnsbl_retval: ", host[0])
		return true
	}

	if score > 25 {
		logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, " score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: spam, dnsbl_retval:", host[0])
		return false
	}

	logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, " score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: ham, dnsbl_retval:", host[0])
	return true
}

func cleanProcessedIps() {

	ticker := time.NewTicker(time.Second * 1800)

	for _ = range ticker.C {
		logger.Log(log.LOG_INFO, "Cleaning the processedIps map.")

		cleanThreshold := time.Now().Unix() - (24 * 60 * 60)

		counter := 0
		processedIps.Lock()
		for k, v := range processedIps.m {
			if v < cleanThreshold {
				delete(processedIps.m, k)
				counter++
			}
		}
		logger.Log(log.LOG_INFO, fmt.Sprintf("Cleaned %v items from processedIps. Current size is: %v", counter, len(processedIps.m)))
		processedIps.Unlock()
	}
}

func cleanProcessingIps() {

	ticker := time.NewTicker(time.Second * 60)

	for _ = range ticker.C {
		logger.Log(log.LOG_INFO, "Cleaning the processingIps map.")

		cleanThreshold := time.Now().Unix() - 60

		counter := 0
		processingIps.Lock()
		for k, v := range processingIps.m {
			if v < cleanThreshold {
				delete(processingIps.m, k)
				counter++
			}
		}
		logger.Log(log.LOG_INFO, fmt.Sprintf("Cleaned %v items from processingIps. Current size is: %v", counter, len(processingIps.m)))
		processingIps.Unlock()

	}
}
