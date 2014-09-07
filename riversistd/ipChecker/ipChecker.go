// Riversist - Monitors network traffic for malicious hosts based on DNSBLs
//
// Copyright 2014 Dolf Schimmel, Freeaqingme.
//
// This Source Code Form is subject to the terms of the two-clause BSD license.
// For its contents, please refer to the LICENSE file.
//
package ipChecker

import (
	"log/syslog"
)

type IpChecker interface {
	IsIpMalicious(ip string, logger Logger) bool
	GetName() string
}

type Config interface{}

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
