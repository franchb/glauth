//go:build !windows
// +build !windows

package logging

import (
	"log"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	ldapliblogmatcher = regexp.MustCompile(`^\d{4}\/\d{1,2}\/\d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2} `)
)

func InitLogging(reqdebug bool, reqsyslog bool, reqstructlog bool) slog.Logger {
	var level slog.Level
	if reqdebug {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	if reqstructlog {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().Format(time.RFC1123Z))
			}
			return a
		}
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	var logr slog.Logger

	if !reqsyslog {
		logr = *slog.New(handler)
	}

	log.SetOutput(customWriter{logr: &logr, structlog: reqstructlog})

	return logr
}

type customWriter struct {
	logr      *slog.Logger
	structlog bool
}

func (e customWriter) Write(p []byte) (int, error) {
	submatchall := ldapliblogmatcher.FindAllString(string(p), 1)
	var msg string
	for _, element := range submatchall {
		msg = strings.TrimSpace(string(p[len(element):]))
	}
	if msg == "" {
		msg = strings.TrimSpace(string(p))
	}
	if e.structlog {
		e.logr.Info(msg, "timestamp", time.Now().Format(time.RFC1123Z))
	} else {
		e.logr.Info(msg)
	}
	return len(p), nil
}
