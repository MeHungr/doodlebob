package main

import (
	"github.com/MeHungr/doodlebob/internal/cli"
)

func main() {
	cli.Heartbeat("8.8.8.8", "192.168.1.77", "6767", "127.0.0.1", "6969")
}
