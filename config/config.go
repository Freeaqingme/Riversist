package config

import (
	"code.google.com/p/gcfg"
	"fmt"
	"riversist/log"
)

type Config struct {
	Riversist struct {
		Interface        string
		Libpcap_Filter   string
		Legit_Ip_Cmd     string
		Malicious_Ip_Cmd string
	}
	ProjectHoneyPot struct {
		Enabled      bool
		Api_Key      string
		Stale_Period int
		Max_Score    int
	}
}

func LoadConfig(cfgFile string, cfg *Config, logger log.Logger) {
	err := gcfg.ReadFileInto(cfg, cfgFile)

	if err != nil {
		logger.Fatal(fmt.Sprintf("Couldn't read config: %s", err))
	}

	if cfg.Riversist.Interface == "" {
		logger.Fatal("Interface cannot be left empty")
	}

	if cfg.ProjectHoneyPot.Enabled && cfg.ProjectHoneyPot.Api_Key == "" {
		logger.Fatal("An API key for Project HoneyPot must be set")
	}
}

func DefaultConfig(cfg *Config) {
	cfg.Riversist.Interface = "eth0"
	cfg.Riversist.Libpcap_Filter = "tcp and ip"

	cfg.ProjectHoneyPot.Enabled = true
	cfg.ProjectHoneyPot.Stale_Period = 14
	cfg.ProjectHoneyPot.Max_Score = 25
}
