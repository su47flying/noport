package cmd

import (
	"noport/client"
	"noport/pkg"
)

func RunClient(cfg *pkg.Config) error {
	c, err := client.New(cfg)
	if err != nil {
		return err
	}
	return c.Run()
}
