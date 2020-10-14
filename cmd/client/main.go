package main

import "log"

func main() {
	// TODO: read username from flag
	err := newSSH("hensoko", "127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}
}
