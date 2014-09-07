// Riversist - Monitor and firewall network traffic based on DNSBLs
//
// Copyright 2014 Dolf Schimmel, Freeaqingme.
//
// This Source Code Form is subject to the terms of the two-clause BSD license.
// For its contents, please refer to the LICENSE file.
//
package ipChecker

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DnsblConfig struct {
	Config
	Host                string
	Malicious_Threshold uint32
}

type DnsblChecker struct {
	IpChecker
	config DnsblConfig
}

func (checker *DnsblChecker) GetName() string {
	return fmt.Sprintf("Dnsbl %s", checker.config.Host)
}

func (checker *DnsblChecker) IsIpMalicious(ip string, logger Logger) bool {

	name := checker.GetName()

	if strings.Index(ip, ".") < 0 {
		// As we don't support IPv6 yet, it is all considered HAM
		return false
	}

	split_ip := strings.Split(ip, ".")
	rev_ip := strings.Join([]string{split_ip[3], split_ip[2], split_ip[1], split_ip[0]}, ".")

	host, err := net.LookupHost(fmt.Sprintf("%v.%v", rev_ip, checker.config.Host))
	if len(host) == 0 {
		logger.Log(LOG_DEBUG, fmt.Sprintf("Received no result from %s: %s", name, err.Error()))
		return false
	}

	// Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
	ret_octets := strings.Split(host[0], ".")
	if len(ret_octets) != 4 || ret_octets[0] != "127" {
		logger.Log(LOG_INFO, fmt.Sprintf("Invalid return value from %s: %s", name, string(host[0])))
		return false
	}

	score, _ := strconv.ParseUint(ret_octets[3], 10, 32)
	if uint32(score) >= checker.config.Malicious_Threshold {
		logger.Log(LOG_INFO, fmt.Sprintf("DNSBL: %s, IP: %s, score: %d, threshold: %d, verdict: malicious, dnsbl_retval: %s", checker.config.Host, ip, score, checker.config.Malicious_Threshold, host[0]))
		return true
	}

	logger.Log(LOG_INFO, fmt.Sprintf("DNSBL: %s, IP: %s, score: %d, threshold: %d, verdict: legit, dnsbl_retval: %s", checker.config.Host, ip, score, checker.config.Malicious_Threshold, host[0]))
	return false

}

func NewDnsblChecker(config DnsblConfig) *DnsblChecker {
	ret := new(DnsblChecker)

	ret.config = config
	return ret
}
