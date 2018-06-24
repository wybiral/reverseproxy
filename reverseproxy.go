// This package implements a reverse proxy that encrypts all traffic using
// AES-CFB. Target servers are expected to share the supplied key and will first
// be sent a 16-byte IV and be expected to send back a 16-byte IV before any
// other communication begins.
package reverseproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"net"
)

// A ReverseProxy stores everything needed to start serving to listeners.
type ReverseProxy struct {
	// Target address to proxy
	targetAddr string
	// AES block from key
	block cipher.Block
}

// Create a new ReverseProxy at that encrypts and proxies traffic to the
// specified targetAddr using a shared key.
func New(targetAddr string, key []byte) (*ReverseProxy, error) {
	// Create AES block from key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	p := &ReverseProxy{
		targetAddr: targetAddr,
		block:      block,
	}
	return p, nil
}

// Create a new TCP listener and call the Serve method.
func (p *ReverseProxy) ListenAndServe(addr string) error {
	// Setup listener
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return p.Serve(ln)
}

// Serve accepts incoming connections on the Listener ln, creating a new service
// goroutine for each. The service goroutines proxy requests to the target
// address and handle IV exchange and encrypted communications.
func (p *ReverseProxy) Serve(ln net.Listener) error {
	// Serve forever
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleConnection(conn)
	}
}

// Handle each incoming connection.
func (p *ReverseProxy) handleConnection(conn net.Conn) {
	defer conn.Close()
	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		log.Fatal(err)
	}
	// Connect to target
	target, err := net.Dial("tcp", p.targetAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer target.Close()
	// Send IV to target before any other communication
	_, err = target.Write(iv)
	if err != nil {
		log.Println(err)
		return
	}
	// Read target IV from connection
	targetIV := make([]byte, aes.BlockSize)
	_, err = target.Read(targetIV)
	if err != nil {
		log.Println(err)
		return
	}
	// Create reader and writer to wrap target conn with stream cipher
	r := decryptReader(target, p.block, targetIV)
	w := encryptWriter(target, p.block, iv)
	// Copy decrypted reader to conn
	go io.Copy(conn, r)
	// Copy conn to encrypted writer
	io.Copy(w, conn)
}

// Wrap a net.Conn instance with an AES stream reader.
func decryptReader(c net.Conn, b cipher.Block, iv []byte) io.Reader {
	return &cipher.StreamReader{S: cipher.NewCFBDecrypter(b, iv), R: c}
}

// Wrap a net.Conn instance with an AES stream writer.
func encryptWriter(c net.Conn, b cipher.Block, iv []byte) io.Writer {
	return &cipher.StreamWriter{S: cipher.NewCFBEncrypter(b, iv), W: c}
}
