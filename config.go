package main

import (
	"github.com/spf13/viper"
	"log"
	"os"
	"time"
)

type config struct {
	KeepAlivePeriod time.Duration
	ConnectTimeout  time.Duration
	Auths           map[string]string
	AsCluster       map[string]string
}

func getConfig(v *viper.Viper, configFile string) *config {
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Get config failed: %s", err)
		os.Exit(1)
	}
	v.SetConfigFile(configFile)
	v.SetConfigType("yaml")
	err := v.ReadInConfig()
	if err != nil {
		log.Printf("Get config failed: %s", err)
		os.Exit(1)
	}
	connectTimeout := v.GetInt("connect_timeout")
	keepAlivePeriod := v.GetInt("keepalive_period")
	auths := v.GetStringMapString("auths")
	asCluster := v.GetStringMapString("as_cluster")
	return &config{
		KeepAlivePeriod: time.Duration(keepAlivePeriod) * time.Second,
		ConnectTimeout:  time.Duration(connectTimeout) * time.Second,
		Auths:           auths,
		AsCluster:       asCluster,
	}
}
