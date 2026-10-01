package cs2

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func closeTestPair(t *testing.T) (*Conn, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	c := &Conn{Conn: &udpConn{UDPConn: local, addr: peer.LocalAddr().(*net.UDPAddr)},
		channels: [4]*dataChannel{newDataChannel(0, 10), nil, newDataChannel(250, 1000), nil}}
	t.Cleanup(func() { c.Close(); peer.Close() })
	return c, peer
}

func expectControl(t *testing.T, peer *net.UDPConn, kind byte) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 32)
	n, _, err := peer.ReadFromUDP(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:n], []byte{magic, kind, 0, 0}) {
		t.Fatalf("control = %x", b[:n])
	}
}

func TestCloseNotifiesPeerOnce(t *testing.T) {
	c, peer := closeTestPair(t)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	expectControl(t, peer, msgClose)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := peer.ReadFromUDP(make([]byte, 32)); err == nil {
		t.Fatal("duplicate close sent another datagram")
	}
}

func TestReadTimeoutClosesSocketAndNotifiesPeer(t *testing.T) {
	c, peer := closeTestPair(t)
	c.Conn.SetDeadline(time.Now().Add(30 * time.Millisecond))
	go c.worker()
	_, _, err := c.ReadCommand()
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read error = %v", err)
	}
	expectControl(t, peer, msgClose)
	if _, err := c.Conn.Write([]byte{magic, msgPing, 0, 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed reader retained its socket: %v", err)
	}
}

func TestPeerCloseAcknowledgesAndUnblocksReader(t *testing.T) {
	c, peer := closeTestPair(t)
	go c.worker()
	peer.WriteToUDP([]byte{magic, msgClose, 0, 0}, c.Conn.LocalAddr().(*net.UDPAddr))
	_, _, err := c.ReadCommand()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("peer close error = %v", err)
	}
	expectControl(t, peer, msgCloseAck)
	if _, err := c.Conn.Write([]byte{magic, msgPing, 0, 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed peer retained its socket: %v", err)
	}
}
