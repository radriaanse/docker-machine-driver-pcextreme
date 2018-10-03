package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/radriaanse/docker-machine-driver-pcextreme"
)

func main() {
	plugin.RegisterDriver(pcextreme.NewDriver("", ""))
}
