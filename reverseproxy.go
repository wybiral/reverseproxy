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
	"time"
)

// A ReverseProxy stores everything needed to start serving.
type ReverseProxy struct {
	// Address to serve proxy on
	proxyAddr string
	// Target address to proxy
	targetAddr string
	// AES block from key
	block cipher.Block
	// Channel for sending shutdown events
	shutdownChan chan struct{}
	// Timeout duration for listener between checking for shutdown signal.
	// Default is 5 seconds.
	ListenerTimeout time.Duration
}

// Create a new ReverseProxy at proxyAddr that encrypts and proxies traffic to
// the specified targetAddr using a shared key.
func New(proxyAddr, targetAddr string, key []byte) (*ReverseProxy, error) {
	// Create AES block from key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	p := &ReverseProxy{
		proxyAddr:       proxyAddr,
		targetAddr:      targetAddr,
		block:           block,
		shutdownChan:    make(chan struct{}),
		ListenerTimeout: 5 * time.Second,
	}
	return p, nil
}

// Start serving the reverse proxy. The target server will be sent an IV and
// will be expected to send back an IV before any communication begins.
func (p *ReverseProxy) Serve() error {
	// Setup listener
	addr, err := net.ResolveTCPAddr("tcp", p.proxyAddr)
	if err != nil {
		return err
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	// Serve forever
	for {
		// Check for shutdown signal
		select {
		case <-p.shutdownChan:
			return nil
		default:
		}
		// Set deadline for listener
		ln.SetDeadline(time.Now().Add(p.ListenerTimeout))
		conn, err := ln.Accept()
		opErr, ok := err.(*net.OpError)
		if ok && opErr.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
		go p.handleConnection(conn)
	}
}

// Signal the reverse proxy server to shutdown.
func (p *ReverseProxy) Shutdown() {
	p.shutdownChan <- struct{}{}
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
