package cmd

import (
	"noport/pkg"
	"noport/server"
)

func RunServer(cfg *pkg.Config) error {
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	return srv.Run()
}
