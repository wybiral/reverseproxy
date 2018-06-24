package reverseproxy_test

import (
	"bytes"
	"github.com/wybiral/reverseproxy"
	"github.com/wybiral/reverseproxy/pkg/backend"
	"io"
	"net"
	"testing"
	"time"
)

const proxyAddr = "127.0.0.1:2000"
const targetAddr = "127.0.0.1:8080"

func TestServe(t *testing.T) {
	key := []byte("????????????????????????????????")
	// Start the target (echo) server
	target := startTarget(t, key)
	defer target.Close()
	// Start the proxy
	proxy := startProxy(t, key)
	defer proxy.Close()
	// Delay for starting listeners
	time.Sleep(time.Second)
	client := startClient(t)
	// Delay for IV handshake
	time.Sleep(time.Second)
	request := []byte("Hello world!")
	response := make([]byte, 1024)
	go client.Write(request)
	// Delay for crypto/write
	time.Sleep(time.Second)
	n, err := client.Read(response)
	if err != nil {
		t.Errorf("client read error: %v", err)
	}
	if bytes.Compare(request, response[:n]) != 0 {
		t.Error("client response doesn't match request")
	}
}

// Start an echo server that handles the encryption/decryption with key
func startTarget(t *testing.T, key []byte) net.Listener {
	target, err := backend.Listen(targetAddr, key)
	if err != nil {
		t.Fatalf("target listen error: %v", err)
	}
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				opErr, ok := err.(*net.OpError)
				errMsg := opErr.Err.Error()
				if ok && errMsg == "use of closed network connection" {
					// This is normal when the target listener has closed
					return
				}
				t.Fatal(err)
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return target
}

// Start the proxy with a key
func startProxy(t *testing.T, key []byte) net.Listener {
	ln, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("proxy create listener error: %v", err)
	}
	p, err := reverseproxy.New(targetAddr, key)
	if err != nil {
		t.Fatalf("proxy create error: %v", err)
	}
	go p.Serve(ln)
	return ln
}

// Connect a TCP client to the proxy
func startClient(t *testing.T) net.Conn {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}
	return conn
}
