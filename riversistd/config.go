package riversistd

import (
	"code.google.com/p/gcfg"
	"fmt"
	"riversist/riversistd/ipChecker"
	//	"riversist/riversistd/log"
)

type config struct {
	Riversist struct {
		Interface        string
		Libpcap_Filter   string
		Legit_Ip_Cmd     string
		Malicious_Ip_Cmd string
	}
	ProjectHoneyPot ipChecker.ProjectHoneyPotConfig
}

func LoadConfig(cfgFile string, cfg *config, logger Logger) {
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

func DefaultConfig(cfg *config) {
	cfg.Riversist.Interface = "eth0"
	cfg.Riversist.Libpcap_Filter = "tcp and ip"

	cfg.ProjectHoneyPot.Enabled = true
	cfg.ProjectHoneyPot.Stale_Period = 14
	cfg.ProjectHoneyPot.Max_Score = 25
}
