// Riversist - Monitors network traffic for malicious hosts based on DNSBLs
//
// Copyright 2014 Dolf Schimmel, Freeaqingme.
//
// This Source Code Form is subject to the terms of the two-clause BSD license.
// For its contents, please refer to the LICENSE file.
//
package riversistd

import (
	"os"
	"os/signal"
	"syscall"
)

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
