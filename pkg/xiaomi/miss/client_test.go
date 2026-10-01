package miss

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type endedMediaConn struct {
	Conn
	closed bool
}

func (c *endedMediaConn) SetDeadline(time.Time) error         { return nil }
func (c *endedMediaConn) ReadPacket() ([]byte, []byte, error) { return nil, nil, io.EOF }
func (c *endedMediaConn) Close() error                        { c.closed = true; return nil }

func TestEndedProducerClosesTransportBeforeReconnect(t *testing.T) {
	conn := &endedMediaConn{}
	p := &Producer{client: &Client{Conn: conn}, opened: time.Now()}
	if err := p.Start(); !errors.Is(err, io.EOF) {
		t.Fatalf("media error = %v", err)
	}
	if !conn.closed {
		t.Fatal("ended producer retained the old camera session")
	}
}

type authTestConn struct {
	Conn
	socket net.Conn
}

func (c *authTestConn) SetDeadline(t time.Time) error     { return c.socket.SetDeadline(t) }
func (c *authTestConn) WriteCommand(uint32, []byte) error { return nil }
func (c *authTestConn) ReadCommand() (uint32, []byte, error) {
	b := make([]byte, 256)
	n, err := c.socket.Read(b)
	return cmdAuthRes, b[:n], err
}

func TestLoginMissingReplyIsBounded(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	result := make(chan error, 1)
	go func() { result <- login(&authTestConn{socket: local}, "test", "test") }()
	select {
	case err := <-result:
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatalf("expected auth timeout, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("missing auth reply left login blocked")
	}
}

func TestLoginSuccessClearsDeadline(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	go func() { _, _ = peer.Write([]byte(`{"result":"success"}`)) }()
	if err := login(&authTestConn{socket: local}, "test", "test"); err != nil {
		t.Fatal(err)
	}
	// A completed login must not leave an eight-second expiry on live media.
	go func() {
		time.Sleep(8500 * time.Millisecond)
		_, _ = peer.Write([]byte("media"))
	}()
	b := make([]byte, 5)
	if _, err := local.Read(b); err != nil {
		t.Fatalf("auth deadline leaked into media read: %v", err)
	}
}
