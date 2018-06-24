package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

// Listener is an implementation of the net.Listener interface that accepts
// encrypted connections. These should be returned from Listen rather than
// created explicitly.
type Listener struct {
	tcpLn *net.TCPListener
	block cipher.Block
}

// Listen announces on the local network address and returns an encrypted
// implementation of the net.Listener interface.
func Listen(addr string, key []byte) (*Listener, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	tcpLn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, err
	}
	ln := &Listener{
		tcpLn: tcpLn,
		block: block,
	}
	return ln, nil
}

// Accept implements the Accept method in the net.Listener interface.
func (ln *Listener) Accept() (net.Conn, error) {
	tcpConn, err := ln.tcpLn.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return newConn(tcpConn, ln.block)
}

// Close stops listening on the TCP address.
// Already Accepted connections are not closed.
func (ln *Listener) Close() error {
	return ln.tcpLn.Close()
}

// Addr returns the listener's network address, a *TCPAddr.
// The Addr returned is shared by all invocations of Addr, so do not modify it.
func (ln *Listener) Addr() net.Addr {
	return ln.tcpLn.Addr()
}
