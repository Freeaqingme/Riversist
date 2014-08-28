package projectHoneyPot

import (
	"fmt"
	"net"
	"riversist/config"
	"riversist/ipChecker"
	"riversist/log"
	"strconv"
	"strings"
	//    "riversist"
)

type IpChecker struct {
	ipChecker.IpChecker
}

func (checker *IpChecker) GetName() string {
	return "projectHoneyPot"
}

func (checker *IpChecker) IsIpMalicious(ip string, logger log.Logger, config config.Config) bool {

	if strings.Index(ip, ".") < 0 {
		// As we don't support IPv6 yet, it is all considered HAM
		return false
	}

	split_ip := strings.Split(ip, ".")
	rev_ip := strings.Join([]string{split_ip[3], split_ip[2], split_ip[1], split_ip[0]}, ".")

	host, err := net.LookupHost(fmt.Sprintf("%v.%v.dnsbl.httpbl.org", config.ProjectHoneyPot.Api_Key, rev_ip))
	if len(host) == 0 {
		logger.Log(log.LOG_DEBUG, "Received no result from httpbl.org:", err.Error())
		return false
	}

	// Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
	ret_octets := strings.Split(host[0], ".")
	if len(ret_octets) != 4 || ret_octets[0] != "127" {
		logger.Log(log.LOG_INFO, "Invalid return value from httpbl.org:", string(host[0]))
		return false
	}

	conf_stale_period := config.ProjectHoneyPot.Stale_Period
	conf_max_score := config.ProjectHoneyPot.Max_Score
	stale_period, _ := strconv.Atoi(ret_octets[1])
	threat_score, _ := strconv.Atoi(ret_octets[2])
	// todo: What to do when stale_period == 0 ?
	score := (conf_stale_period / stale_period) * threat_score

	// Prefer it to be at least conf_stale_period days stale with a score of < conf_max_score
	if stale_period > conf_stale_period {
		logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: stale, stale_period:", strconv.Itoa(stale_period), ", stale_threshold: ", strconv.Itoa(conf_stale_period), " verdict: ham, dnsbl_retval: ", host[0])
		return false
	}

	if score > conf_max_score {
		logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: legit, dnsbl_retval:", host[0])
		return false
	}

	logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(conf_max_score), ", verdict: legit, dnsbl_retval:", host[0])
	return false

}
