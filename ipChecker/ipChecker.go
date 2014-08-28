package ipChecker

import (
	"riversist/config"
	"riversist/log"
)

type IpChecker interface {
	IsIpMalicious(ip string, logger log.Logger, config config.Config) bool
	GetName() string
}
