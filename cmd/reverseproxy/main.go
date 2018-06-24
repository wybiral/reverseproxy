package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"github.com/wybiral/reverseproxy"
	"golang.org/x/crypto/pbkdf2"
	"log"
)

func main() {
	// Setup proxy flags
	var proxyHost string
	flag.StringVar(&proxyHost, "host", "0.0.0.0", "Host to serve proxy on")
	var proxyPort int
	flag.IntVar(&proxyPort, "port", 8080, "Port to serve proxy on")
	// Setup target flag
	var targetAddr string
	flag.StringVar(&targetAddr, "target", "localhost:80", "Target address")
	// Setup password flags
	var password string
	flag.StringVar(&password, "pass", "", "Password for PBKDF2 key derivation")
	var salt string
	flag.StringVar(&salt, "salt", "--salt--", "Salt for PBKDF2")
	var rounds int
	flag.IntVar(&rounds, "rounds", 4096, "Rounds used for PBKDF2")
	// Parse flags
	flag.Parse()
	if len(password) == 0 {
		log.Fatal("Missing required -pass password flag")
	}
	// Derive key from password
	key := pbkdf2.Key([]byte(password), []byte(salt), rounds, 32, sha1.New)
	// Create and start proxy server
	proxyAddr := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
	p, err := reverseproxy.New(targetAddr, key)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Target set to", targetAddr)
	log.Println("Serving proxy at", proxyAddr)
	err = p.ListenAndServe(proxyAddr)
	if err != nil {
		log.Fatal(err)
	}
}
