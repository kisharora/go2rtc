package cs2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func decodeCloudReport(cipher []byte) []byte {
	key := deriveCryptoKey([]byte(cs2CryptoKey))
	out := make([]byte, len(cipher))
	var prev byte
	for i, b := range cipher {
		out[i] = b ^ selectTableElement(key, prev)
		prev = b
	}
	return out
}

func TestRegisterCloudSessionReportsEveryRelayAndPreservesPeer(t *testing.T) {
	c, peer := closeTestPair(t)
	uc := c.Conn.(*udpConn)
	var relays []*net.UDPAddr
	var listeners []*net.UDPConn
	for i := 0; i < 3; i++ {
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { relay.Close() })
		listeners = append(listeners, relay)
		relays = append(relays, relay.LocalAddr().(*net.UDPAddr))
	}
	localIP, wanIP := net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.2")
	actualPeer := peer.LocalAddr().(*net.UDPAddr)
	// The completed handshake must remove its expiring read/write deadlines.
	uc.SetDeadline(time.Now().Add(-time.Second))
	// Give only writes enough time to publish the final reports.
	uc.SetWriteDeadline(time.Now().Add(time.Second))
	conn, err := registerCloudSession(uc, "ABCDEF-123456-GHIJK", relays, localIP, 40000, wanIP, 50000, actualPeer, 42, time.Now().Add(-750*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	for _, relay := range listeners {
		relay.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 128)
		n, _, err := relay.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 88 || !bytes.Equal(buf[:4], []byte{magic, msgCloudAuth, 0, 84}) {
			t.Fatalf("report header/length = %x/%d", buf[:4], n)
		}
		p := decodeCloudReport(buf[4:n])
		if got := binary.BigEndian.Uint32(p[20:24]); got != 42 {
			t.Fatalf("SDK handle = %d", got)
		}
		if got := binary.BigEndian.Uint16(p[28:30]); got < 750 || got > 3000 {
			t.Fatalf("connection duration = %dms", got)
		}
		for _, offset := range []int{36, 52, 68} {
			if !bytes.Equal(p[offset:offset+2], []byte{0, 2}) {
				t.Fatalf("family at %d", offset)
			}
		}
		if binary.LittleEndian.Uint16(p[38:40]) != 40000 || !bytes.Equal(p[40:44], []byte{1, 2, 0, 192}) {
			t.Fatal("local address mismatch")
		}
		if binary.LittleEndian.Uint16(p[54:56]) != 50000 || !bytes.Equal(p[56:60], []byte{2, 100, 51, 198}) {
			t.Fatal("observed WAN address mismatch")
		}
		if binary.LittleEndian.Uint16(p[70:72]) != uint16(actualPeer.Port) || !bytes.Equal(p[72:76], []byte{1, 0, 0, 127}) {
			t.Fatal("responding peer mismatch")
		}
	}
	if conn.RemoteAddr().String() != actualPeer.String() {
		t.Fatalf("media destination = %s", conn.RemoteAddr())
	}
	if _, err := conn.Write([]byte{magic, msgPing, 0, 0}); err != nil {
		t.Fatal(err)
	}
	expectControl(t, peer, msgPing)
	peer.WriteToUDP([]byte{magic, msgPong, 0, 0}, uc.LocalAddr().(*net.UDPAddr))
	if _, err := conn.Read(make([]byte, 32)); err != nil {
		t.Fatalf("handshake deadline retained: %v", err)
	}
}

func TestRegisterCloudSessionFailureClosesSocket(t *testing.T) {
	c, peer := closeTestPair(t)
	uc := c.Conn.(*udpConn)
	conn, err := registerCloudSession(uc, "invalid", nil, nil, 0, nil, 0, peer.LocalAddr().(*net.UDPAddr), 1, time.Now())
	if err == nil || conn != nil {
		t.Fatalf("invalid report = %v, %v", conn, err)
	}
	if _, err := uc.Write([]byte{magic, msgPing, 0, 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed registration retained socket: %v", err)
	}
}

func TestCloudHandshakeWaitsForUDPReady(t *testing.T) {
	// A separate loopback address avoids the service's real outbound sockets.
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 55), Port: 32100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	tcpSent := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 512)
		announced := false
		sentTCP := false
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			if buf[1] == msgCloudConnect && !announced {
				announced = true
				info := make([]byte, 20)
				info[0], info[1], info[3], info[5] = magic, msgNatPunch, 16, 2
				binary.LittleEndian.PutUint16(info[6:8], 32100)
				copy(info[8:12], []byte{55, 0, 0, 127})
				relay.WriteToUDP(info, from)
			}
			if buf[1] == 0x67 && !sentTCP {
				sentTCP = true
				ready := make([]byte, 48)
				ready[0], ready[1], ready[3] = magic, msgP2PRdyTCP, 44
				relay.WriteToUDP(ready, from)
				tcpSent <- from
			}
		}
	}()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan dialResult, 1)
	go func() {
		conn, err := cloudHandshake("ABCDEF-123456-GHIJK", "127.0.0.55")
		result <- dialResult{conn, err}
	}()
	var client *net.UDPAddr
	select {
	case client = <-tcpSent:
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not reach the punching stage")
	}
	select {
	case r := <-result:
		if r.conn != nil {
			r.conn.Close()
		}
		t.Fatalf("UDP handshake completed on TCP-ready: %v", r.err)
	case <-time.After(150 * time.Millisecond):
	}
	ready := make([]byte, 24)
	ready[0], ready[1], ready[3] = magic, msgP2PRdyUDP, 20
	relay.WriteToUDP(ready, client)
	select {
	case r := <-result:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.conn.Close()
	case <-time.After(time.Second):
		t.Fatal("UDP-ready did not complete the handshake promptly")
	}
}
