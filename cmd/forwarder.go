package cmd

import (
	"noport/pkg"
	"noport/server"
)

func RunForwarder(cfg *pkg.Config) error {
	fwd, err := server.NewForwarder(cfg)
	if err != nil {
		return err
	}
	return fwd.Run()
}
