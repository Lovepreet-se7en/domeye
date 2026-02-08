package main

import (
	"github.com/Lovepreet-se7en/domeye/cmd"
	"log"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
