package main

import (
	"flag"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"net"
	"os"
)

var (
	listenAddr  = flag.String("listen", ":3000", "listen address")
	backendAddr = flag.String("backend", "127.0.0.1:7000", "backend server")
	debug       = flag.Bool("debug", false, "debug mode")
	configFile  = flag.String("config", "./as-proxy.yml", "config file")
)

func main() {
	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	v := viper.New()
	config := getConfig(v, *configFile)

	authsMap := make(map[string][]byte)
	for user, password := range config.Auths {
		hash, err := hashPassword(password)
		if err != nil {
			log.Error().Msgf("Hash password failed: %s", err)
			os.Exit(1)
		}
		authsMap[user] = hash
	}

	asClusterMap := make(map[string][]byte)
	for server, proxy := range config.AsCluster {
		proxyByte := []byte(proxy)
		asClusterMap[server] = proxyByte
	}

	log.Info().Msgf("Proxying from %v to %v", *listenAddr, *backendAddr)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Error().Msgf("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	target := DialProxy{
		Addr:            *backendAddr,
		KeepAlivePeriod: config.KeepAlivePeriod,
		DialTimeout:     config.ConnectTimeout,
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("Failed to accept connection: %s", err)
			os.Exit(1)
		}
		go target.HandleConn(conn, authsMap, asClusterMap)
	}
}
