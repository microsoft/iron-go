package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/WatchBeam/iron-go"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	secret = kingpin.Flag("secret", "Cookie encryption password").Required().Short('s').String()
	value  = kingpin.Flag("value", "Cookie contents. If not provided, reads from stdin.").Short('v').String()
	seal   = kingpin.Command("seal", "Encrypts the cookie")
	unseal = kingpin.Command("unseal", "Decrypts the cookie")
)

func main() {
	cmd := kingpin.Parse()
	vault := iron.New(iron.Options{Secret: []byte(*secret)})

	input := *value
	if input == "" {
		raw, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal("Error reading from standard input: ", err)
		}
		input = string(raw)
	}
	input = strings.TrimSpace(input)

	switch cmd {
	case seal.FullCommand():
		sealed, err := vault.Seal([]byte(input))
		if err != nil {
			log.Fatal("Error sealing bytes", err)
		}
		os.Stdout.Write([]byte(sealed))

	case unseal.FullCommand():
		sealed, err := vault.Unseal(input)
		if err != nil {
			log.Fatal("Error unsealing input: ", err)
		}
		os.Stdout.Write(sealed)
	}
}
