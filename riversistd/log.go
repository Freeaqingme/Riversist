// Riversist - Monitors network traffic for malicious hosts based on DNSBLs
//
// Copyright 2014 Dolf Schimmel, Freeaqingme.
//
// This Source Code Form is subject to the terms of the two-clause BSD license.
// For its contents, please refer to the LICENSE file.
//
package riversistd

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"strings"
	"time"
)

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

type Logger struct {
	SyslogWriter *syslog.Writer
	Writer       *io.Writer
	logLevel     int
}

func (l Logger) Log(level syslog.Priority, msgArray ...string) {
	if int(level) > l.logLevel {
		return
	}

	msg := strings.Join(msgArray, " ")
	l.syslog(level, msg)

	msg = fmt.Sprintf("%v [%d]: %v\n", time.Now(), os.Getpid(), strings.Trim(msg, "\n"))

	ioWriter := *l.Writer
	ioWriter.Write([]byte(msg))
}

func (l Logger) Fatal(msgArray ...string) {
	msg := strings.Join(msgArray, " ")
	l.syslog(syslog.LOG_EMERG, msg)

	panic(msg)
}

func (l Logger) New(logLevel int) Logger {
	syslogWriter, e := syslog.New(syslog.LOG_NOTICE, "riversist")
	if e != nil {
		log.Fatal("Could not open syslog writer: ", e)
	}

	ioWriter := io.MultiWriter(os.Stdout)
	logger := Logger{syslogWriter, &ioWriter, logLevel}

	if logLevel < 0 || logLevel > 7 {
		logger.logLevel = 7
		logger.Fatal(fmt.Sprintf("Invalid loglevel %v given. Value must be in range of 0..7", logLevel))
	}

	return logger
}

func (l Logger) syslog(level syslog.Priority, msg string) {
	w := l.SyslogWriter

	switch level {
	case syslog.LOG_EMERG:
		w.Emerg(msg)
	case syslog.LOG_ALERT:
		w.Alert(msg)
	case syslog.LOG_CRIT:
		w.Crit(msg)
	case syslog.LOG_ERR:
		w.Err(msg)
	case syslog.LOG_WARNING:
		w.Warning(msg)
	case syslog.LOG_NOTICE:
		w.Notice(msg)
	case syslog.LOG_INFO:
		w.Info(msg)
	case syslog.LOG_DEBUG:
		w.Debug(msg)
	}
}
