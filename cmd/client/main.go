package main

import "log"

func main() {
	err := newSSH("127.0.0.1:2022")
	if err != nil {
		log.Fatalf(err.Error())
	}
}
