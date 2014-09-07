// Riversist - Monitors network traffic for malicious hosts based on DNSBLs
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

type ProjectHoneyPotConfig struct {
	Config
	Enabled      bool
	Api_Key      string
	Stale_Period int
	Max_Score    int
}

type ProjectHoneyPotChecker struct {
	IpChecker
	config ProjectHoneyPotConfig
}

func (checker *ProjectHoneyPotChecker) GetName() string {
	return "projectHoneyPot"
}

func (checker *ProjectHoneyPotChecker) IsIpMalicious(ip string, logger Logger) bool {

	if strings.Index(ip, ".") < 0 {
		// As we don't support IPv6 yet, it is all considered HAM
		return false
	}

	split_ip := strings.Split(ip, ".")
	rev_ip := strings.Join([]string{split_ip[3], split_ip[2], split_ip[1], split_ip[0]}, ".")

	host, err := net.LookupHost(fmt.Sprintf("%v.%v.dnsbl.httpbl.org", checker.config.Api_Key, rev_ip))
	if len(host) == 0 {
		logger.Log(LOG_DEBUG, "Received no result from httpbl.org:", err.Error())
		return false
	}

	// Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
	ret_octets := strings.Split(host[0], ".")
	if len(ret_octets) != 4 || ret_octets[0] != "127" {
		logger.Log(LOG_INFO, "Invalid return value from httpbl.org:", string(host[0]))
		return false
	}

	conf_stale_period := checker.config.Stale_Period
	conf_max_score := checker.config.Max_Score
	stale_period, _ := strconv.Atoi(ret_octets[1])
	threat_score, _ := strconv.Atoi(ret_octets[2])
	if stale_period == 0 {
		stale_period = 1 // Prevent division by zero, still get a decent score
	}
	score := (conf_stale_period / stale_period) * threat_score

	// Prefer it to be at least conf_stale_period days stale with a score of < conf_max_score
	if stale_period > conf_stale_period {
		logger.Log(LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: stale, stale_period:", strconv.Itoa(stale_period), ", stale_threshold: ", strconv.Itoa(conf_stale_period), " verdict: ham, dnsbl_retval: ", host[0])
		return false
	}

	if score > conf_max_score {
		logger.Log(LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: malicious, dnsbl_retval:", host[0])
		return true
	}

	logger.Log(LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: legit, dnsbl_retval:", host[0])
	return false

}

func NewProjectHoneyPotChecker(config ProjectHoneyPotConfig) *ProjectHoneyPotChecker {
	ret := new(ProjectHoneyPotChecker)

	ret.config = config
	return ret
}
