package frontend

import (
	"net/http"
)

// RunAPI provides a basic REST API
func RunAPI(opts ...Option) {
	options := newOptions(opts...)
	log := options.Logger
	cfg := options.Config

	if cfg.TLS {
		log.Info().Str("address", cfg.Listen).Msg("Starting HTTPS server")

		if err := http.ListenAndServeTLS(cfg.Listen, cfg.Cert, cfg.Key, nil); err != nil {
			log.Error().Err(err).Msg("error starting HTTPS server")
		}

		return
	}

	log.Info().Str("address", cfg.Listen).Msg("Starting HTTP server")

	if err := http.ListenAndServe(cfg.Listen, nil); err != nil {
		log.Error().Err(err).Msg("error starting HTTP server")
	}

}
