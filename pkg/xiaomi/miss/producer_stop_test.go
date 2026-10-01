package miss

import (
	"github.com/AlexxIT/go2rtc/pkg/core"
	"testing"
)

type stopTestConn struct {
	Conn
	version          string
	commands, closes int
}

func (c *stopTestConn) Version() string                   { return c.version }
func (c *stopTestConn) WriteCommand(uint32, []byte) error { c.commands++; return nil }
func (c *stopTestConn) Close() error                      { c.closes++; return nil }

func TestCS2StopClosesOnlyItsSession(t *testing.T) {
	conn := &stopTestConn{version: "CS2"}
	client := &Client{Conn: conn, key: make([]byte, 32)}
	p := &Producer{Connection: core.Connection{Transport: client}, client: client}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if conn.commands != 0 {
		t.Fatal("CS2 close sent a global video-stop command")
	}
	if conn.closes != 1 {
		t.Fatalf("closed sessions = %d", conn.closes)
	}
}

func TestNonCS2StopKeepsExplicitVideoStop(t *testing.T) {
	conn := &stopTestConn{version: "TUTK"}
	client := &Client{Conn: conn, key: make([]byte, 32)}
	p := &Producer{Connection: core.Connection{Transport: client}, client: client}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if conn.commands != 1 || conn.closes != 1 {
		t.Fatalf("commands=%d closes=%d", conn.commands, conn.closes)
	}
}
