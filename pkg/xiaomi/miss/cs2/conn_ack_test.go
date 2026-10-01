package cs2

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestMediaAckBatchPreservesSequencesAndBoundsSize(t *testing.T) {
	var wire bytes.Buffer
	a := &mediaAckBatch{writer: &wire}
	for i := 0; i < 17; i++ {
		if err := a.Add(uint16(65530 + i)); err != nil {
			t.Fatal(err)
		}
		if i < 16 && wire.Len() != 0 {
			t.Fatal("partial batch sent prematurely")
		}
	}
	b := wire.Bytes()
	if len(b) != 42 || binary.BigEndian.Uint16(b[2:4]) != 38 || binary.BigEndian.Uint16(b[6:8]) != 17 || b[5] != 2 {
		t.Fatalf("ACK framing = %x", b)
	}
	for i := 0; i < 17; i++ {
		if got := binary.BigEndian.Uint16(b[8+2*i:]); got != uint16(65530+i) {
			t.Fatalf("sequence %d = %d", i, got)
		}
	}
	wire.Reset()
	if err := a.Add(12); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != 10 || binary.BigEndian.Uint16(wire.Bytes()[8:10]) != 12 {
		t.Fatal("partial batch lost or duplicated")
	}
}

func TestWorkerFlushesPartialMediaAck(t *testing.T) {
	c, peer := closeTestPair(t)
	go c.worker()
	// A complete empty media frame, fragmented as one CH2 datagram.
	b := make([]byte, 44)
	b[0], b[1], b[4], b[5] = magic, msgDrw, magicDrw, 2
	binary.BigEndian.PutUint16(b[2:4], 40)
	binary.BigEndian.PutUint32(b[8:12], 32)
	if _, err := peer.WriteToUDP(b, c.Conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 128)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte{magic, msgDrwAck, 0, 6, magicDrw, 2, 0, 1, 0, 0}) {
		t.Fatalf("partial ACK = %x", buf[:n])
	}
}

func TestCommandAckRequiresMatchingChannelAndSequence(t *testing.T) {
	c, peer := closeTestPair(t)
	go c.worker()
	result := make(chan error, 1)
	go func() { result <- c.WriteCommand(0x1001, nil) }()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 8 || buf[1] != msgDrw || buf[5] != 0 {
		t.Fatalf("request = %x", buf[:n])
	}
	local := c.Conn.LocalAddr().(*net.UDPAddr)
	for _, wrong := range [][]byte{
		{magic, msgDrwAck, 0, 6, magicDrw, 2, 0, 1, 0, 0},
		{magic, msgDrwAck, 0, 6, magicDrw, 0, 0, 1, 0xff, 0xff},
	} {
		if _, err := peer.WriteToUDP(wrong, local); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			t.Fatalf("unrelated ACK completed command: %v", err)
		case <-time.After(30 * time.Millisecond):
		}
	}
	good := []byte{magic, msgDrwAck, 0, 8, magicDrw, 0, 0, 2, 0xff, 0xff, 0, 0}
	peer.WriteToUDP(good, local)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("matching command ACK did not complete promptly")
	}
	if c.cmdAck.Load() != nil {
		t.Fatal("completed command retained ACK callback")
	}
}
