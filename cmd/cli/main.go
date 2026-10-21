package main

import (
	"github.com/MeHungr/doodlebob/internal/cli"
)

func main() {
	cli.SendCommand("8.8.8.8", "192.168.1.77", "6767", "touch /home/mehungr/hi.txt")
}
