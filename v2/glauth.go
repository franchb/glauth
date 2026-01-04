package glauth

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/glauth/glauth/v2/internal/toml"
	"github.com/glauth/glauth/v2/internal/version"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/frontend"
	"github.com/glauth/glauth/v2/pkg/logging"
	"github.com/glauth/glauth/v2/pkg/server"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/rs/zerolog"
)

var (
	log zerolog.Logger

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
	stats.General.Set("version", stats.Stringer(version.Version))

	// web API
	if activeConfig.API.Enabled {
		log.Info().Msg("Web API enabled")

		go frontend.RunAPI(
			frontend.Logger(log),
			frontend.Config(&activeConfig.API),
		)
	}

	var err error

	s, err := server.NewServer(
		server.Logger(log),
		server.Config(activeConfig),
	)

	if err != nil {
		log.Error().Err(err).Msg("could not create server")
		os.Exit(1)
	}

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Error().Err(err).Msg("could not start LDAP server")
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
	log.Info().Msg("AP exit")
	os.Exit(0)
}
