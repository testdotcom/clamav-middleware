package observability

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

func InitJSONLogger(logLevel slog.Level) {
	Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetLogLoggerLevel(logLevel)
}
