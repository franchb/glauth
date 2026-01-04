package tls

import (
	tls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
)

var (
	log slog.Logger
)

func SetLogger(logger slog.Logger) {
	log = logger
}

var secureCipherSuites = []uint16{
	// TLS 1.3 cipher suites (automatically used when TLS 1.3 is negotiated)
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,

	// TLS 1.2 ECDHE cipher suites (Forward Security)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

	// Additional secure TLS 1.2 cipher suites (CBC with HMAC-SHA256)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	//	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	//	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
}

// MakeTLS generates a tls.Config
func MakeTLS(clientCert, key []byte, legacy bool) (*tls.Config, error) {
	if clientCert == nil && key == nil {
		return new(tls.Config), nil
	}

	var err error

	cert, err := tls.X509KeyPair(clientCert, key)

	if err != nil {
		return nil, err
	}

	log.Debug("key", "value", string(key))
	log.Debug("client.certificate", "value", string(clientCert))
	log.Debug("certificate", "value", cert)

	if err != nil {
		return nil, err
	}

	// Get SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()

	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		log.Warn("Using empty cert-pool", "err", err)
	} else {
		log.Info("Using system cert-pool")
	}

	for _, cert := range DecodePEM(clientCert).Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Error("issue parsing cert PEM", "err", err)
		}
		rootCAs.AddCert(x509Cert)
	}

	log.Debug("root.ca", "value", rootCAs)
	log.Debug("certificates", "value", []tls.Certificate{cert})

	if legacy {
		return &tls.Config{
			RootCAs:                  rootCAs,
			MinVersion:               tls.VersionTLS10,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CipherSuites:             nil,
			Certificates:             []tls.Certificate{cert},
		}, nil
	}

	return &tls.Config{
		RootCAs:                  rootCAs,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites:             secureCipherSuites,
		Certificates:             []tls.Certificate{cert},
	}, nil
}

// DecodePEM builds a PEM certificate object
func DecodePEM(certPEM []byte) tls.Certificate {
	var cert tls.Certificate
	var certDER *pem.Block
	for {
		certDER, certPEM = pem.Decode(certPEM)
		if certDER == nil {
			break
		}
		if certDER.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDER.Bytes)
		}
	}

	return cert
}

func CipherSuiteNames(suites []uint16) []string {
	var names []string
	for _, suite := range suites {
		names = append(names, tls.CipherSuiteName(suite))
	}
	return names
}
