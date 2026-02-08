package main

import (
	"domeye/cmd"
	"log"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
