package glauth

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"log/slog"

	"github.com/glauth/glauth/v2/internal/toml"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/logging"
	"github.com/glauth/glauth/v2/pkg/server"
)

var (
	log slog.Logger

	activeConfig = &config.Config{}
)

func Start(ctx context.Context) {
	data := ""
	var err error
	activeConfig, err = toml.NewConfig(data)

	if err != nil {
		fmt.Println("Configuration file error")
		fmt.Println(err)
		os.Exit(1)
	}

	log = logging.InitLogging(activeConfig.Debug, activeConfig.Syslog, activeConfig.StructuredLog)

	startService(ctx)
}
func startService(ctx context.Context) {
	// stats

	var err error

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
	)

	if err != nil {
		log.Error("could not create server", "err", err)
		os.Exit(1)
	}

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Error("could not start LDAP server", "err", err)
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until we receive our signal.
	select {
	case <-c:
	case <-ctx.Done():
	}

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	s.Shutdown()

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	log.Info("AP exit")
	os.Exit(0)
}
