// sighup support
// state file
package riversistd

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
//	"riversist/riversistd/config"
	"riversist/riversistd/ipChecker"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type ipMap struct {
	sync.RWMutex
	m map[string]int64
}

var logger Logger
var processedIps ipMap
var processingIps ipMap
var ownIps ipMap
var Config = *new(config)
var checkers []ipChecker.IpChecker

func Main() {

	processedIps = ipMap{m: make(map[string]int64)}
	processingIps = ipMap{m: make(map[string]int64)}
	ownIps = ipMap{m: make(map[string]int64)}

	setProcessName("riversist")

	logLevel := flag.Int("loglevel", 5, "Syslog Loglevel (0-7, Emerg-Debug)")
	configFile := flag.String("config", "", "Path to Config File")
	flag.Parse()

	logger = logger.New(*logLevel)
	logger.Log(LOG_NOTICE, "Starting...")
	defer logger.Log(LOG_CRIT, "Exiting...")

	ProjectHoneypotConfig := *new(ipChecker.ProjectHoneyPotConfig)
	Config.ProjectHoneyPot = ProjectHoneypotConfig
	DefaultConfig(&Config)
	if *configFile != "" {
		LoadConfig(*configFile, &Config, logger)
	}

	go pruneIpMap(&processingIps, 60, 60, "processingIps")
	go pruneIpMap(&processedIps, (24 * 60 * 60), 1800, "processedIps")

	setOwnIps()
	initializeCheckers()

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
		logger.Log(LOG_NOTICE, "Received signal: "+signal.String())

		switch signal {
		case syscall.SIGINT, syscall.SIGTERM:
			quit = true
		case syscall.SIGHUP:
			quit = false
		}

		if quit {
			quit = false
			logger.Log(LOG_CRIT, "Terminating...")
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

func initializeCheckers() {
	projectHoneyPot := new(ipChecker.ProjectHoneyPotChecker)
	checkers = []ipChecker.IpChecker{projectHoneyPot}
}

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
		logger.Log(LOG_DEBUG, fmt.Sprintf("%v is in the ownIps map. Skipping", ip))
		ownIps.RUnlock()
		return
	}
	ownIps.RUnlock()

	processedIps.RLock()
	if _, ok := processedIps.m[ip]; ok {
		logger.Log(LOG_DEBUG, fmt.Sprintf("%v has already been evaluated. Skipping", ip))
		processedIps.RUnlock()
		return
	}
	processedIps.RUnlock()

	processingIps.RLock()
	if _, ok := processingIps.m[ip]; ok {
		logger.Log(LOG_DEBUG, fmt.Sprintf("%v is already being evaluated. Skipping", ip))
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

	dnsbl := ""
	// Ideally we would do this concurrently. But who cares, really...
	for _, checker := range checkers {
		if checker.IsIpMalicious(ip, logger, &Config.ProjectHoneyPot) {
			dnsbl = checker.GetName()
			break
		}
	}

	if dnsbl != "" {
		logger.Log(LOG_NOTICE, fmt.Sprintf("Evaluted IP: %s, table: malicious. DNSBL: %s", ip, dnsbl))
		cmdStr = Config.Riversist.Malicious_Ip_Cmd
	} else {
		logger.Log(LOG_NOTICE, fmt.Sprintf("Evaluated IP: %s, table: legit", ip))
		cmdStr = Config.Riversist.Legit_Ip_Cmd
	}

	if cmdStr == "" {
		logger.Log(LOG_DEBUG, "Not calling any exetuable cause it hasn't been configured")
		return
	}

	cmdStr = fmt.Sprintf(cmdStr, ip)
	cmdArr := strings.Split(cmdStr, " ")
	cmd := exec.Command(cmdArr[0], cmdArr[1:len(cmdArr)]...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		logger.Log(LOG_ERR, fmt.Sprintf("Could not execute %s: %s", cmdStr, err.Error()))
	}

}

func pruneIpMap(ipMap *ipMap, interval int, threshold int, name string) {

	ticker := time.NewTicker(time.Second * time.Duration(interval))

	for _ = range ticker.C {
		logger.Log(LOG_INFO, fmt.Sprintf("Cleaning the %s map", name))

		unixTimeThreshold := time.Now().Unix() - int64(threshold)

		counter := 0
		ipMap.Lock()
		for k, v := range ipMap.m {
			if v < unixTimeThreshold {
				delete(ipMap.m, k)
				counter++
			}
		}
		logger.Log(LOG_INFO, fmt.Sprintf("Cleaned %v items from %s. Current size is: %v", counter, name, len(ipMap.m)))
		ipMap.Unlock()
	}

}
