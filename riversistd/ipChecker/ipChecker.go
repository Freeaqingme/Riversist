package ipChecker

import (
	"log/syslog"
)

type IpChecker interface {
	IsIpMalicious(ip string, logger Logger, config Config) bool
	GetName() string
}

type Config interface {
	GetI(key string) int
	GetS(key string) string
}

const (
	LOG_EMERG syslog.Priority = iota
	LOG_ALERT
	LOG_CRIT
	LOG_ERR
	LOG_WARNING
	LOG_NOTICE
	LOG_INFO
	LOG_DEBUG
)

type Logger interface {
	Fatal(msg ...string)
	Log(level syslog.Priority, msgArray ...string)
}
