package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"time"
)

// Conn is an encrypted implementation of the net.Conn interface.
// These should be returned from Listen rather than created explicitly.
type Conn struct {
	tcpConn *net.TCPConn
	r       io.Reader
	w       io.Writer
}

// Establish IV handshake and return encrypted Conn interface.
func newConn(tcpConn *net.TCPConn, block cipher.Block) (*Conn, error) {
	// Read IV from remote
	remoteIV := make([]byte, aes.BlockSize)
	_, err := tcpConn.Read(remoteIV)
	if err != nil {
		return nil, err
	}
	// Generate local IV and write to remote
	localIV := make([]byte, aes.BlockSize)
	_, err = rand.Read(localIV)
	if err != nil {
		return nil, err
	}
	_, err = tcpConn.Write(localIV)
	if err != nil {
		return nil, err
	}
	// Wrap tcpConn in cipher streams
	streamIn := cipher.NewCFBDecrypter(block, remoteIV)
	r := &cipher.StreamReader{S: streamIn, R: tcpConn}
	streamOut := cipher.NewCFBEncrypter(block, localIV)
	w := &cipher.StreamWriter{S: streamOut, W: tcpConn}
	return &Conn{tcpConn: tcpConn, r: r, w: w}, nil
}

// Read implements the net.Conn Read method.
func (c *Conn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// Write implements the net.Conn Write method.
func (c *Conn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.tcpConn.Close()
}

// LocalAddr returns the local network address. The Addr returned is shared by
// all invocations of LocalAddr, so do not modify it.
func (c *Conn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

// RemoteAddr returns the remote network address. The Addr returned is shared by
// all invocations of RemoteAddr, so do not modify it.
func (c *Conn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}
