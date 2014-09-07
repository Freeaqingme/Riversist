// Riversist - Monitors network traffic for malicious hosts based on DNSBLs
//
// Copyright 2014 Dolf Schimmel, Freeaqingme.
//
// This Source Code Form is subject to the terms of the two-clause BSD license.
// For its contents, please refer to the LICENSE file.
//

// sighup support
// state file
package riversistd

import (
	"bytes"
	"flag"
	"fmt"
	"os/exec"
	"riversist/riversistd/ipChecker"
	"strings"
	"sync"
	"time"
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
	if Config.Riversist.Auto_Expiry_Time != 0 {
		go pruneIpMap(&processedIps, Config.Riversist.Auto_Expiry_Time, Config.Riversist.Prune_Interval, "processedIps")
	}

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

func initializeCheckers() {
	checkers = make([]ipChecker.IpChecker, 0)

	if Config.ProjectHoneyPot.Enabled {
		projectHoneyPot := ipChecker.NewProjectHoneyPotChecker(Config.ProjectHoneyPot)
		checkers = append(checkers, projectHoneyPot)
	}

	for _, dnsblConfig := range Config.Dnsbl {
		checkers = append(checkers, ipChecker.NewDnsblChecker(*dnsblConfig))
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
		if checker.IsIpMalicious(ip, logger) {
			dnsbl = checker.GetName()
			break
		}
	}

	if dnsbl != "" {
		logger.Log(LOG_NOTICE, fmt.Sprintf("Evaluted IP: %s, verdict: malicious. DNSBL: %s", ip, dnsbl))
		cmdStr = Config.Riversist.Malicious_Ip_Cmd
	} else {
		logger.Log(LOG_NOTICE, fmt.Sprintf("Evaluated IP: %s, verdict: legit", ip))
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

func pruneIpMap(ipMap *ipMap, interval uint, threshold uint, name string) {

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
