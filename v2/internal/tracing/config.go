package tracing

import (
	"log/slog"
)

type Config struct {
	OtelHTTPEndpoint string
	OtelGRPCEndpoint string
	Logger           *slog.Logger

	Enabled bool
}

func NewConfig(enabled bool, otelGRPCEndpoint, otelHTTPEndpoint string, logger *slog.Logger) *Config {
	c := new(Config)

	c.OtelGRPCEndpoint = otelGRPCEndpoint
	c.OtelHTTPEndpoint = otelHTTPEndpoint
	c.Logger = logger
	c.Enabled = enabled

	return c
}
