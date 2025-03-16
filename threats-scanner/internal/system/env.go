package system

import (
	"log/slog"
	"os"
	"strconv"
	"time"
)

var (
	LogLevel              slog.Level
	RequestTimeout        time.Duration
	MaxConcurrentRequests int
	Port                  string
)

func init() {
	var err error

	level := os.Getenv("LOG_LEVEL")
	switch level {
	case "DEBUG":
		LogLevel = slog.LevelDebug
	case "WARN":
		LogLevel = slog.LevelWarn
	case "ERROR":
		LogLevel = slog.LevelError
	default:
		LogLevel = slog.LevelInfo
	}

	RequestTimeout, err = time.ParseDuration(os.Getenv("REQ_TIMEOUT"))
	if err != nil {
		RequestTimeout = 60 * time.Second
	}

	MaxConcurrentRequests, err = strconv.Atoi(os.Getenv("MAX_CONN"))
	if err != nil {
		MaxConcurrentRequests = 10
	}

	Port = os.Getenv("SCANNER_PORT")
	if _, err = strconv.Atoi(Port); err != nil {
		Port = ":8080"
	} else {
		Port = ":" + Port
	}
}
