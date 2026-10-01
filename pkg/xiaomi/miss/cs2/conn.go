package cs2

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func Dial(host, transport string) (*Conn, error) {
	conn, err := handshake(host, transport)
	if err != nil {
		return nil, err
	}

	_, isTCP := conn.(*tcpConn)

	c := &Conn{
		Conn:  conn,
		isTCP: isTCP,
		channels: [4]*dataChannel{
			newDataChannel(0, 10), nil, newDataChannel(250, 1000), nil,
		},
	}
	go c.worker()
	return c, nil
}

// DialCloud establishes a cs2 connection via Mi-Cloud relay (UDP/32100)
// using NAT hole-punching. Required for cameras that do not expose the
// LAN port 32108 directly — typically the MJA1-secure-element generation
// of Xiaomi cameras (e.g. xiaomi.camera.c302n, xiaomi.camera.cw701,
// isa.camera.hlc7), which only stream via Mi-Cloud.
//
// p2pID is the device identifier from the Mi-Cloud vendor_params,
// of the form "PREFIX-NUM-SUFFIX" (e.g. "ABCDEF-123456-GHIJK").
// relayHost is the Mi-Cloud relay IP (one of the published Alibaba Cloud
// pool addresses, e.g. 47.236.156.107, 47.88.30.183, 47.88.30.225).
func DialCloud(p2pID, relayHost string) (*Conn, error) {
	conn, err := cloudHandshake(p2pID, relayHost)
	if err != nil {
		return nil, err
	}

	_, isTCP := conn.(*tcpConn)

	c := &Conn{
		Conn:  conn,
		isTCP: isTCP,
		channels: [4]*dataChannel{
			newDataChannel(0, 10), nil, newDataChannel(250, 1000), nil,
		},
	}
	go c.worker()
	return c, nil
}

// cs2CryptoKey is the universal key string used by the CS2-Network
// P2P_Proprietary_Encrypt cipher, extracted from camera firmware
// disassembly. The same constant is found in cameras of multiple
// vendors that license the CS2-Network SDK (see e.g. the VStarcam
// reverse engineering by BrownFineSecurity).
const cs2CryptoKey = "SSD@cs2-network."

// cs2LookupTable is the 256-byte permutation used by the CS2-Network
// cipher. Identical to the table observed in VStarcam firmware.
var cs2LookupTable = [256]byte{
	0x7c, 0x9c, 0xe8, 0x4a, 0x13, 0xde, 0xdc, 0xb2, 0x2f, 0x21, 0x23, 0xe4, 0x30, 0x7b, 0x3d, 0x8c,
	0xbc, 0x0b, 0x27, 0x0c, 0x3c, 0xf7, 0x9a, 0xe7, 0x08, 0x71, 0x96, 0x00, 0x97, 0x85, 0xef, 0xc1,
	0x1f, 0xc4, 0xdb, 0xa1, 0xc2, 0xeb, 0xd9, 0x01, 0xfa, 0xba, 0x3b, 0x05, 0xb8, 0x15, 0x87, 0x83,
	0x28, 0x72, 0xd1, 0x8b, 0x5a, 0xd6, 0xda, 0x93, 0x58, 0xfe, 0xaa, 0xcc, 0x6e, 0x1b, 0xf0, 0xa3,
	0x88, 0xab, 0x43, 0xc0, 0x0d, 0xb5, 0x45, 0x38, 0x4f, 0x50, 0x22, 0x66, 0x20, 0x7f, 0x07, 0x5b,
	0x14, 0x98, 0x1d, 0x9b, 0xa7, 0x2a, 0xb9, 0xa8, 0xcb, 0xf1, 0xfc, 0x49, 0x47, 0x06, 0x3e, 0xb1,
	0x0e, 0x04, 0x3a, 0x94, 0x5e, 0xee, 0x54, 0x11, 0x34, 0xdd, 0x4d, 0xf9, 0xec, 0xc7, 0xc9, 0xe3,
	0x78, 0x1a, 0x6f, 0x70, 0x6b, 0xa4, 0xbd, 0xa9, 0x5d, 0xd5, 0xf8, 0xe5, 0xbb, 0x26, 0xaf, 0x42,
	0x37, 0xd8, 0xe1, 0x02, 0x0a, 0xae, 0x5f, 0x1c, 0xc5, 0x73, 0x09, 0x4e, 0x69, 0x24, 0x90, 0x6d,
	0x12, 0xb3, 0x19, 0xad, 0x74, 0x8a, 0x29, 0x40, 0xf5, 0x2d, 0xbe, 0xa5, 0x59, 0xe0, 0xf4, 0x79,
	0xd2, 0x4b, 0xce, 0x89, 0x82, 0x48, 0x84, 0x25, 0xc6, 0x91, 0x2b, 0xa2, 0xfb, 0x8f, 0xe9, 0xa6,
	0xb0, 0x9e, 0x3f, 0x65, 0xf6, 0x03, 0x31, 0x2e, 0xac, 0x0f, 0x95, 0x2c, 0x5c, 0xed, 0x39, 0xb7,
	0x33, 0x6c, 0x56, 0x7e, 0xb4, 0xa0, 0xfd, 0x7a, 0x81, 0x53, 0x51, 0x86, 0x8d, 0x9f, 0x77, 0xff,
	0x6a, 0x80, 0xdf, 0xe2, 0xbf, 0x10, 0xd7, 0x75, 0x64, 0x57, 0x76, 0xf3, 0x55, 0xcd, 0xd0, 0xc8,
	0x18, 0xe6, 0x36, 0x41, 0x62, 0xcf, 0x99, 0xf2, 0x32, 0x4c, 0x67, 0x60, 0x61, 0x92, 0xca, 0xd3,
	0xea, 0x63, 0x7d, 0x16, 0xb6, 0x8e, 0xd4, 0x68, 0x35, 0xc3, 0x52, 0x9d, 0x46, 0x44, 0x1e, 0x17,
}

// deriveCryptoKey returns the 4-byte stream-cipher state derived from a
// key string. Mirrors the SDK's key-schedule (truncated at 20 bytes).
func deriveCryptoKey(key []byte) [4]byte {
	var c [4]byte
	n := len(key)
	if n > 20 {
		n = 20
	}
	for i := 0; i < n; i++ {
		b := key[i]
		c[0] += b
		c[1] -= b
		c[2] += b / 3
		c[3] ^= b
	}
	return c
}

// selectTableElement returns the keystream byte for the given previous
// ciphertext byte: table[(prev + c_key[prev & 3]) & 0xff].
func selectTableElement(c [4]byte, prev byte) byte {
	return cs2LookupTable[byte(prev+c[prev&3])]
}

// encryptP2P applies the CS2-Network P2P_Proprietary_Encrypt cipher
// to plaintext. The cipher is a stream cipher with previous-ciphertext-byte
// feedback; the same routine decrypts when fed ciphertext, because the
// feedback variable always reads from the cipher side.
func encryptP2P(plain []byte) []byte {
	c := deriveCryptoKey([]byte(cs2CryptoKey))
	out := make([]byte, len(plain))
	var prev byte = 0
	for i, p := range plain {
		out[i] = p ^ selectTableElement(c, prev)
		prev = out[i]
	}
	return out
}

// buildP2PIDBlock encodes a p2p_id string of the form "PREFIX-NUM-SUFFIX"
// into the 20-byte canonical block used by 0x20 (connect) and 0x41 (punch):
//
//	[ 0.. 5] prefix (6 bytes, null-padded)  e.g. "ABCDEF"
//	[ 6.. 7] padding 0x00 0x00
//	[ 8..11] num (uint32 big-endian)        e.g. 123456 -> 0x0001E240
//	[12..16] suffix (5 bytes, null-padded)  e.g. "GHIJK"
//	[17..19] padding 0x00 0x00 0x00
func buildP2PIDBlock(p2pID string) ([]byte, error) {
	parts := strings.Split(p2pID, "-")
	if len(parts) != 3 {
		return nil, fmt.Errorf("cs2 cloud: invalid p2p_id format: %s", p2pID)
	}
	prefix := parts[0]
	numStr := parts[1]
	suffix := parts[2]

	if len(prefix) > 6 {
		return nil, fmt.Errorf("cs2 cloud: p2p_id prefix too long: %s", prefix)
	}
	if len(suffix) > 5 {
		return nil, fmt.Errorf("cs2 cloud: p2p_id suffix too long: %s", suffix)
	}

	num, err := strconv.ParseUint(numStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("cs2 cloud: invalid p2p_id num %q: %w", numStr, err)
	}

	block := make([]byte, 20)
	copy(block[0:6], []byte(prefix))
	binary.BigEndian.PutUint32(block[8:12], uint32(num))
	copy(block[12:17], []byte(suffix))
	return block, nil
}

// buildCloudConnect builds the 0x20 connect-request message (40 bytes total:
// 4-byte header + 36-byte payload, made of the 20-byte p2p_id block and a
// 16-byte nonce/timestamp tail).
func buildCloudConnect(p2pID string, localIP net.IP, localPort uint16) ([]byte, error) {
	block, err := buildP2PIDBlock(p2pID)
	if err != nil {
		return nil, err
	}

	// Relay-validated format: block[0:20] + zeros[20:22] + BigEndian unix
	// timestamp at [22:26]. Any sockaddr bytes in the tail (family/port/IP)
	// flip the 0x21 status to ff000000 and no 0x40 ever arrives.
	payload := make([]byte, 36)
	copy(payload[0:20], block)
	binary.BigEndian.PutUint32(payload[22:26], uint32(time.Now().Unix()))

	msg := make([]byte, 4+36)
	msg[0] = magic
	msg[1] = msgCloudConnect
	binary.BigEndian.PutUint16(msg[2:4], 36)
	copy(msg[4:], payload)
	return msg, nil
}

// buildCloudPunch builds the 0x41 (msgPunchPkt) frame with the 20-byte
// p2p_id block as payload. In cloud-relay mode the camera silently drops
// the empty 4-byte punch used by the LAN handshake and only responds when
// the punch frame carries the p2p_id block (so the cam can identify which
// session the punch belongs to).
func buildCloudPunch(p2pID string) ([]byte, error) {
	block, err := buildP2PIDBlock(p2pID)
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 4+20)
	msg[0] = magic
	msg[1] = msgPunchPkt
	binary.BigEndian.PutUint16(msg[2:4], 20)
	copy(msg[4:], block)
	return msg, nil
}

// cloudAuthUnknownBlock is the 16-byte payload at plaintext offset 20-35
// of the 0xF9 auth message. Captured verbatim from a Mi-Home iOS
// handshake; the byte pattern (sparse, small values) looks like protocol
// flags or channel constants rather than client-specific data, and
// transmitting it verbatim works against the relay and camera. Zeroing
// this block caused the camera to silently drop subsequent punch packets.
// Values not verified against a second account; treat as opaque.
var cloudAuthUnknownBlock = [16]byte{
	0x00, 0x00, 0x00, 0x06, 0x00, 0x14, 0x00, 0x01,
	0x00, 0x88, 0x00, 0x00, 0x7a, 0x00, 0x00, 0x00,
}

// buildCloudAuth builds the 0xF9 session-auth message (88 bytes total)
// by encrypting an 84-byte plaintext that carries the device_uid block,
// an opaque flags block and the client's own UDP address.
//
// Plaintext layout (84 bytes, verified by decrypting a captured 0xF9):
//
//	[ 0..19] device_uid     = encoded p2p_id (prefix + num_be + suffix)
//	[20..35] unknown        = 16-byte opaque flags/counter block
//	[36..51] local_address  = Xiaomi sockaddr-style: 2B family (00 00) +
//	                          2B port LE + 4B ipv4 reverse-LE + 8B pad
//	[52..67] wan_address    = same format; equal to local when the client
//	                          sits on a public IP without NAT
//	[68..83] device_address = zeros (the camera-side LAN address is
//	                          unknown to us; the relay reports the cam's
//	                          WAN address back in its 0x40 reply anyway)
//
// Zero-filling everything past device_uid produces a working relay
// response (0x21 ACK, 0x40 punch info) but the camera then ignores
// punches — likely because the cam validates the addresses against
// the source it sees on subsequent packets.
func buildCloudAuth(p2pID string, localIP net.IP, localPort uint16) ([]byte, error) {
	uidBlock, err := buildP2PIDBlock(p2pID)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, 84)
	copy(plain[0:20], uidBlock)
	copy(plain[20:36], cloudAuthUnknownBlock[:])

	if v4 := localIP.To4(); v4 != nil && localPort != 0 {
		// local_addr [36..51]
		binary.LittleEndian.PutUint16(plain[38:40], localPort)
		plain[40] = v4[3]
		plain[41] = v4[2]
		plain[42] = v4[1]
		plain[43] = v4[0]
		// wan_addr [52..67] — identical to local for clients without
		// a NAT layer in front (e.g. a server with a public IP).
		binary.LittleEndian.PutUint16(plain[54:56], localPort)
		plain[56] = v4[3]
		plain[57] = v4[2]
		plain[58] = v4[1]
		plain[59] = v4[0]
	}

	// Post-submit findings from the PR author's Frida captures of the
	// Mi-Home Android app: plaintext byte 23 is 0x01 (not 0x06), and
	// bytes 28-29 carry a per-session sequence ID (not 0x0088).
	plain[23] = 0x01
	binary.BigEndian.PutUint16(plain[28:30], uint16(time.Now().UnixNano()))

	cipher := encryptP2P(plain)

	msg := make([]byte, 4+len(cipher))
	msg[0] = magic
	msg[1] = msgCloudAuth
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(cipher)))
	copy(msg[4:], cipher)
	return msg, nil
}

func buildRelayMediaAuth(p2pID string, localIP net.IP, localPort uint16, wanIP net.IP, wanPort uint16, mediaIP net.IP, mediaPort uint16, sessionID uint32, connectMs uint16) ([]byte, error) {
	uidBlock, err := buildP2PIDBlock(p2pID)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, 84)
	copy(plain[0:20], uidBlock)
	copy(plain[20:36], cloudAuthUnknownBlock[:])

	// Xiaomi's final F9 reports the SDK session handle and connection time.
	// Fresh captures increment the handle across direct sessions; 2 is not
	// a relay-media connection type, and the duration is not a random ID.
	binary.BigEndian.PutUint32(plain[20:24], sessionID)
	binary.BigEndian.PutUint16(plain[28:30], connectMs)

	// local_address [36..51]
	if v4 := localIP.To4(); v4 != nil && localPort != 0 {
		plain[36], plain[37] = 0x00, 0x02
		binary.LittleEndian.PutUint16(plain[38:40], localPort)
		plain[40] = v4[3]
		plain[41] = v4[2]
		plain[42] = v4[1]
		plain[43] = v4[0]
	}

	// wan_address [52..67]
	if wanIP == nil || wanPort == 0 {
		wanIP = localIP
		wanPort = localPort
	}
	if v4 := wanIP.To4(); v4 != nil && wanPort != 0 {
		plain[52], plain[53] = 0x00, 0x02
		binary.LittleEndian.PutUint16(plain[54:56], wanPort)
		plain[56] = v4[3]
		plain[57] = v4[2]
		plain[58] = v4[1]
		plain[59] = v4[0]
	}

	// device_address [68..83]: the chosen media session endpoint
	if v4 := mediaIP.To4(); v4 != nil && mediaPort != 0 {
		plain[68], plain[69] = 0x00, 0x02
		binary.LittleEndian.PutUint16(plain[70:72], mediaPort)
		plain[72] = v4[3]
		plain[73] = v4[2]
		plain[74] = v4[1]
		plain[75] = v4[0]
	}

	cipher := encryptP2P(plain)

	msg := make([]byte, 4+len(cipher))
	msg[0] = magic
	msg[1] = msgCloudAuth
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(cipher)))
	copy(msg[4:], cipher)
	return msg, nil
}

var cloudSessionCounter atomic.Uint32

// registerCloudSession mirrors the F9 reports sent to every lookup relay
// after Xiaomi has received P2P-ready, before it authenticates on CH0.
// Use the observed WAN mapping and the actual responding peer, and keep
// subsequent command/media writes addressed to that peer.
func registerCloudSession(uc *udpConn, p2pID string, relays []*net.UDPAddr, localIP net.IP, localPort uint16, wanIP net.IP, wanPort uint16, peer *net.UDPAddr, sessionID uint32, started time.Time) (net.Conn, error) {
	ms := time.Since(started).Milliseconds()
	if ms > 65535 {
		ms = 65535
	}
	if ms < 0 {
		ms = 0
	}
	report, err := buildRelayMediaAuth(p2pID, localIP, localPort, wanIP, wanPort, peer.IP, uint16(peer.Port), sessionID, uint16(ms))
	if err == nil {
		for _, relay := range relays {
			if _, err = uc.UDPConn.WriteToUDP(report, relay); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = uc.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = uc.Close()
		return nil, fmt.Errorf("cs2 cloud: register session: %w", err)
	}
	uc.addr = peer
	return uc, nil
}

// detectOutboundIP returns the local IPv4 address the OS would use to
// reach dest. Uses Go's UDP-dial trick — no packet is sent, only the
// routing table is consulted. Returns nil on error, in which case
// buildCloudAuth leaves the address fields zeroed.
func detectOutboundIP(dest string) net.IP {
	conn, err := net.Dial("udp", net.JoinHostPort(dest, "1"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	if u, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return u.IP
	}
	return nil
}

// cloudHandshake performs the cs2 cloud-relay handshake against the
// Mi-Cloud relay at relayHost:32100. Steps:
//
//  1. Send 0x20 (connect request) and 0xF9 (encrypted session auth) to
//     the relay; the relay replies with 0x21 (ACK) and 0x40 (NAT-punch
//     info containing the camera's external address).
//  2. Switch the UDP socket's remote to the camera's address from 0x40
//     and send 0x41 (msgPunchPkt) carrying the p2p_id block.
//  3. Wait for 0x42 (P2P-ready UDP) from the camera and return.
//
// Cloud mode is UDP-only: TCP would require TCP hole-punching from both
// sides, which is not feasible behind typical NATs.
// i2-region relay cluster observed in Xiaomi Home captures (2026-09-06):
// the app dials every member so the camera's relay learns the session no
// matter which one the camera is registered on.
var i2Relays = []string{"35.200.188.130", "34.100.251.170", "35.200.206.254"}

func siblingRelays(relayHost string) []string {
	host := relayHost
	if h, _, err := net.SplitHostPort(relayHost); err == nil {
		host = h
	}
	for _, r := range i2Relays {
		if r == host {
			return i2Relays
		}
	}
	return []string{host}
}

func cloudHandshake(p2pID, relayHost string) (net.Conn, error) {
	started := time.Now()
	sessionID := cloudSessionCounter.Add(1)
	udp, err := newUDPConn(relayHost, 32100)
	if err != nil {
		return nil, err
	}

	uc := udp.(*udpConn)

	var localPort uint16
	if la, ok := uc.UDPConn.LocalAddr().(*net.UDPAddr); ok {
		localPort = uint16(la.Port)
	}
	localIP := detectOutboundIP(relayHost)
	relayAddrs := make([]*net.UDPAddr, 0, 4)
	for _, rip := range siblingRelays(relayHost) {
		relayAddrs = append(relayAddrs, &net.UDPAddr{IP: net.ParseIP(rip), Port: 32100})
	}

	req20, err := buildCloudConnect(p2pID, localIP, localPort)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	reqF9, err := buildCloudAuth(p2pID, localIP, localPort)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}

	block, berr := buildP2PIDBlock(p2pID)
	if berr != nil {
		_ = udp.Close()
		return nil, berr
	}
	req67 := make([]byte, 0, 24)
	req67 = append(req67, magic, 0x67, 0x00, 0x14)
	req67 = append(req67, block...)

	ping := []byte{magic, 0x00, 0x00, 0x00}

	fmt.Printf("cs2 dbg tx20 %x\ncs2 dbg tx67 %x\n", req20, req67)
	// ---- Phase A: ping + 0x20 burst to EVERY relay (app-verified) ----
	for _, ra := range relayAddrs {
		uc.addr = ra
		_, _ = uc.Write(ping)
	}
	for _, ra := range relayAddrs {
		uc.addr = ra
		if _, err = uc.Write(req20); err != nil {
			_ = udp.Close()
			return nil, fmt.Errorf("cs2 cloud: send 0x20: %w", err)
		}
	}

	buf := make([]byte, 1500)
	var natInfo []byte
	lanPunch, lanPunchErr := buildCloudPunch(p2pID)
	if lanPunchErr != nil {
		_ = udp.Close()
		return nil, lanPunchErr
	}
	// Every public address the relays reported for the camera.
	var camPubs []*net.UDPAddr
	// The camera's LAN addresses. Reachable when the camera shares the
	// server's LAN; otherwise the punches go nowhere.
	var camLAN []*net.UDPAddr
	var mediaToks []handoffTok
	var wanIP net.IP
	var wanPort uint16
	finish := func(peer *net.UDPAddr) (net.Conn, error) {
		return registerCloudSession(uc, p2pID, relayAddrs, localIP, localPort, wanIP, wanPort, peer, sessionID, started)
	}
	// Fail fast and let a fresh attempt (new socket, new NAT port) try
	// again: Xiaomi Home has its punch info in 40 ms (PCAPdroid 2026-10-01).
	deadline := time.Now().Add(10 * time.Second)
	lastResend := time.Now()
	sent67 := false

	collect := func(n int) {
		if n >= 4 && buf[0] == magic {
			switch buf[1] {
			case 0x40, 0x82, 0x69, 0x01, 0x21, 0x84, 0x28, 0x71, 0x73, 0x81:
				fmt.Printf("cs2 dbg rx t=0x%02x: %x\n", buf[1], buf[:n])
			}
		}
		if n < 4 || buf[0] != magic {
			return
		}
		switch buf[1] {
		case 0x01:
			if n >= 12 {
				wanPort = binary.LittleEndian.Uint16(buf[6:8])
				wanIP = net.IPv4(buf[11], buf[10], buf[9], buf[8])
				fmt.Printf("cs2 dbg rx 0x01: STUN mapped wan=%s:%d\n", wanIP, wanPort)
			}
		case msgNatPunch:
			if n >= 12 {
				port := int(binary.LittleEndian.Uint16(buf[6:8]))
				ip := net.IPv4(buf[11], buf[10], buf[9], buf[8])
				fmt.Printf("cs2 dbg rx 0x40: %s:%d (private=%v)\n", ip, port, ip.IsPrivate())
				if !ip.IsPrivate() && !ip.IsLoopback() && ip.To4() != nil {
					seen := false
					for _, a := range camPubs {
						if a.IP.Equal(ip) && a.Port == port {
							seen = true
						}
					}
					if !seen {
						camPubs = append(camPubs, &net.UDPAddr{IP: ip, Port: port})
					}
					natInfo = make([]byte, n)
					copy(natInfo, buf[:n])
				} else if natInfo == nil {
					natInfo = make([]byte, n)
					copy(natInfo, buf[:n])
				}
				if ip.IsPrivate() && ip.To4() != nil {
					seen := false
					for _, a := range camLAN {
						if a.IP.Equal(ip) && a.Port == port {
							seen = true
						}
					}
					if !seen {
						camLAN = append(camLAN, &net.UDPAddr{IP: ip, Port: port})
						// Punch the LAN at once: on the same LAN this is the
						// whole connection (Xiaomi Home: video in 0.08 s).
						for dp := -3; dp <= 3; dp++ {
							uc.addr = &net.UDPAddr{IP: ip, Port: port + dp}
							_, _ = uc.Write(lanPunch)
						}
					}
				}
			}
		case msgMediaHandoff:
			// each 0x82 pairs a relay-media endpoint with a 4-byte session
			// token in its tail — the 0x83 punch must echo that token
			if n >= 16 {
				var tk [4]byte
				copy(tk[:], buf[n-4:n])
				dup := false
				for _, e := range mediaToks {
					if e.token == tk {
						dup = true
						break
					}
				}
				if !dup {
					port := binary.LittleEndian.Uint16(buf[6:8])
					ip := net.IPv4(buf[11], buf[10], buf[9], buf[8])
					mediaToks = append(mediaToks, handoffTok{addr: &net.UDPAddr{IP: ip, Port: int(port)}, token: tk})
				}
			}
		}
	}

	// ---- Phase B: wait for 0x40, resend 0x20 (app resends x9), 0x67 x3 ----
	for natInfo == nil {
		if time.Now().After(deadline) {
			_ = udp.Close()
			return nil, fmt.Errorf("cs2 cloud: timeout waiting for 0x40 NAT-punch info")
		}
		if time.Since(lastResend) > 1*time.Second {
			for i := 0; i < 3; i++ {
				_, _ = uc.Write(req20)
			}
			lastResend = time.Now()
		}
		_ = uc.UDPConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := uc.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			_ = udp.Close()
			return nil, fmt.Errorf("cs2 cloud: read relay: %w", err)
		}
		collect(n)
		if natInfo != nil && !sent67 {
			sent67 = true
			// app: 0x20 resend burst right after the punch-infos, then 0x67 x3
			for i := 0; i < 3; i++ {
				_, _ = uc.Write(req20)
			}
			for i := 0; i < 3; i++ {
				_, _ = uc.Write(req67)
				time.Sleep(30 * time.Millisecond)
			}
		}
	}

	if len(natInfo) < 12 {
		_ = udp.Close()
		return nil, fmt.Errorf("cs2 cloud: 0x40 too short (%d bytes)", len(natInfo))
	}
	camPort := binary.LittleEndian.Uint16(natInfo[6:8])
	camIP := net.IPv4(natInfo[11], natInfo[10], natInfo[9], natInfo[8])
	camAddr := &net.UDPAddr{IP: camIP, Port: int(camPort)}

	punch, err := buildCloudPunch(p2pID)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	// latestCamAddr re-parses the newest 0x40; sweepCam punches the camera's
	// public address across port±3 (LAN addresses can't route from the server)
	latestCamAddr := func() *net.UDPAddr {
		if len(natInfo) < 12 {
			return camAddr
		}
		return &net.UDPAddr{
			IP:   net.IPv4(natInfo[11], natInfo[10], natInfo[9], natInfo[8]),
			Port: int(binary.LittleEndian.Uint16(natInfo[6:8])),
		}
	}
	sweepCam := func() {
		targets := camPubs
		if ca := latestCamAddr(); len(targets) == 0 &&
			!ca.IP.IsPrivate() && !ca.IP.IsLoopback() && ca.IP.To4() != nil {
			targets = []*net.UDPAddr{ca}
		}
		targets = append(append([]*net.UDPAddr{}, targets...), camLAN...)
		for _, ca := range targets {
			for dp := -3; dp <= 3; dp++ {
				uc.addr = &net.UDPAddr{IP: ca.IP, Port: ca.Port + dp}
				_, _ = uc.Write(punch)
			}
		}
	}

	// ---- Phase C: fast collect 0x82 endpoints while racing direct punch ----
	// Xiaomi Home's direct punch succeeds within ~50 ms; the shop's router
	// moves the camera's port, so keep sweeping port±3 for 1.5 s before
	// any fallback (the relay paths below take seconds when they fail).
	sweepCam()
	cEnd := time.Now().Add(1500 * time.Millisecond)
	lastSweep := time.Now()
	for time.Now().Before(cEnd) {
		if time.Since(lastSweep) > 250*time.Millisecond {
			sweepCam()
			lastSweep = time.Now()
		}
		_ = uc.UDPConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, from, err := uc.UDPConn.ReadFromUDP(buf)
		if err == nil {
			collect(n)
			if n >= 4 && buf[0] == magic && from != nil {
				if buf[1] == msgP2PRdyUDP {
					fmt.Printf("cs2 dbg direct punch SUCCESS (early) from %s\n", from)
					return finish(from)
				}
				if buf[1] == msgPunchPkt {
					fmt.Printf("cs2 dbg rx msgPunchPkt early from %s\n", from)
					uc.addr = from
					_, _ = uc.Write(punch)
					_, _ = uc.Write([]byte{magic, msgP2PRdyUDP, 0x00, 0x00})
				}
			}
		}
	}

	// ---- Phase E: relay-media session (app-exact, PCAPdroid 2026-09-06) ----
	// The 0x83 punch must ECHO the per-0x82 session token; a random nonce is
	// ignored by relay-media. Choreography: 0x70 hello to every endpoint,
	// first 0x71 responder is chosen, 0x72 to it, 0x73 {nonce, port},
	// 0x80 introduce x5 to the relay (block17 + zeros4 + 0x02 + portLE +
	// ipREV + zeros8 + nonce4) tells the camera where the session lives,
	// 0x84/0x28 arrive from the session server on an ephemeral port, echo the
	// 0x28 (flag byte -> 02), then 0xF9 auth x3 to the relay. The p2p block
	// is 17 bytes, so the punch payload = token4 + block17 + zeros7 = 0x1C.
	if len(mediaToks) > 0 {
		punchTokens := func() {
			toks := mediaToks
			if len(toks) > 12 {
				toks = toks[len(toks)-12:]
			}
			for _, tk := range toks {
				p83 := make([]byte, 0, 32)
				p83 = append(p83, magic, msgMediaPunch, 0x00, 0x1C)
				p83 = append(p83, tk.token[:]...)
				p83 = append(p83, block[:17]...) // block17: block20 minus 3 pad zeros
				p83 = append(p83, 0, 0, 0, 0, 0, 0, 0)
				uc.addr = tk.addr
				for i := 0; i < 4; i++ {
					_, _ = uc.Write(p83)
				}
			}
		}
		punchTokens()
		for _, tk := range mediaToks {
			uc.addr = tk.addr
			_, _ = uc.Write([]byte{magic, 0x70, 0x00, 0x00})
		}

		relaySeen := make(map[string]*net.UDPAddr, len(relayAddrs))
		for _, ra := range relayAddrs {
			relaySeen[ra.String()] = ra
		}
		var chosen *net.UDPAddr
		var sessNonce [4]byte
		var sessPort uint16
		got73 := false
		stageEnd := time.Now().Add(600 * time.Millisecond)
		for time.Now().Before(stageEnd) && chosen == nil {
			_ = uc.UDPConn.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
			n, from, err := uc.UDPConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			collect(n)
			if n >= 4 && buf[0] == magic && from != nil {
				if buf[1] == 0x71 {
					chosen = from
				} else if buf[1] == msgP2PRdyUDP {
					fmt.Printf("cs2 dbg direct punch SUCCESS (stage 1) from %s\n", from)
					return finish(from)
				} else if buf[1] == msgPunchPkt {
					uc.addr = from
					_, _ = uc.Write(punch)
					_, _ = uc.Write([]byte{magic, msgP2PRdyUDP, 0x00, 0x00})
				}
			}
		}
		if chosen == nil {
			chosen = mediaToks[0].addr
		}
		uc.addr = chosen
		_, _ = uc.Write([]byte{magic, 0x72, 0x00, 0x00})
		stageEnd = time.Now().Add(800 * time.Millisecond)
		for time.Now().Before(stageEnd) && !got73 {
			_ = uc.UDPConn.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
			n, from, err := uc.UDPConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			collect(n)
			if n >= 4 && buf[0] == magic && from != nil {
				if n >= 12 && buf[1] == 0x73 && from.IP.Equal(chosen.IP) && from.Port == chosen.Port {
					copy(sessNonce[:], buf[4:8])
					sessPort = binary.BigEndian.Uint16(buf[8:10])
					got73 = true
					fmt.Printf("cs2 dbg 73: chosen=%s sessPort=%d nonce=%x\n", chosen, sessPort, sessNonce)
				} else if buf[1] == msgP2PRdyUDP {
					fmt.Printf("cs2 dbg direct punch SUCCESS (stage 2) from %s\n", from)
					return finish(from)
				} else if buf[1] == msgPunchPkt {
					uc.addr = from
					_, _ = uc.Write(punch)
					_, _ = uc.Write([]byte{magic, msgP2PRdyUDP, 0x00, 0x00})
				}
			}
		}

		var intro []byte
		var sessAddr *net.UDPAddr
		var p83Sess []byte
		if got73 {
			ip4 := chosen.IP.To4()
			intro = make([]byte, 0, 44)
			intro = append(intro, magic, 0x80, 0x00, 0x28)
			intro = append(intro, block[:17]...) // block17: payload must total 40B
			intro = append(intro, 0, 0, 0, 0)
			intro = append(intro, 0x02)
			var pl [2]byte
			binary.LittleEndian.PutUint16(pl[:], sessPort)
			intro = append(intro, pl[:]...)
			intro = append(intro, ip4[3], ip4[2], ip4[1], ip4[0])
			intro = append(intro, 0, 0, 0, 0, 0, 0, 0, 0)
			intro = append(intro, sessNonce[:]...)

			sessAddr = &net.UDPAddr{IP: chosen.IP, Port: int(sessPort)}
			p83Sess = make([]byte, 0, 32)
			p83Sess = append(p83Sess, magic, msgMediaPunch, 0x00, 0x1C)
			p83Sess = append(p83Sess, sessNonce[:]...)
			p83Sess = append(p83Sess, block[:17]...)
			p83Sess = append(p83Sess, 0, 0, 0, 0, 0, 0, 0)

			fmt.Printf("cs2 dbg tx80 immediate: relays=%d chosen=%s sessPort=%d nonce=%x\n", len(relaySeen), chosen, sessPort, sessNonce)
			for _, ra := range relaySeen {
				uc.addr = ra
				for i := 0; i < 5; i++ {
					_, _ = uc.Write(intro)
				}
			}
			uc.addr = sessAddr
			for i := 0; i < 10; i++ {
				_, _ = uc.Write(p83Sess)
			}
		}

		var sessFrom *net.UDPAddr
		var sessExpiry time.Time
		pEnd := time.Now().Add(5 * time.Second)
		_ = udp.SetDeadline(time.Now().Add(6 * time.Second))
		var lastPunch, lastSessPunch, lastIntro, last67, last41 time.Time
		for time.Now().Before(pEnd) {
			if time.Since(lastPunch) > 1500*time.Millisecond {
				punchTokens()
				lastPunch = time.Now()
			}
			if sessAddr != nil && p83Sess != nil && time.Since(lastSessPunch) > 250*time.Millisecond {
				uc.addr = sessAddr
				for i := 0; i < 4; i++ {
					_, _ = uc.Write(p83Sess)
				}
				lastSessPunch = time.Now()
			}
			if time.Since(last41) > 500*time.Millisecond {
				// relay-forwarded punches: the camera only escalates to
				// relay-media after these reach it and its replies to us fail
				for _, ra := range relaySeen {
					uc.addr = ra
					_, _ = uc.Write(punch)
				}
				sweepCam()
				last41 = time.Now()
			}
			if time.Since(last67) > 2500*time.Millisecond {
				for _, ra := range relaySeen {
					uc.addr = ra
					_, _ = uc.Write(req67)
				}
				last67 = time.Now()
			}
			if intro != nil && time.Since(lastIntro) > 2000*time.Millisecond {
				fmt.Printf("cs2 dbg tx80: relays=%d chosen=%s sessPort=%d\n", len(relaySeen), chosen, sessPort)
				for _, ra := range relaySeen {
					uc.addr = ra
					for i := 0; i < 5; i++ {
						_, _ = uc.Write(intro)
					}
				}
				lastIntro = time.Now()
			}
			_ = uc.UDPConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := uc.UDPConn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					if sessFrom != nil && time.Now().After(sessExpiry) {
						break
					}
					continue
				}
				break
			}
			collect(n)
			if from.Port == 32100 {
				if _, ok := relaySeen[from.String()]; !ok {
					relaySeen[from.String()] = from
					fmt.Printf("cs2 dbg relay seen %s\n", from)
				}
			}
			if n < 4 || buf[0] != magic || from == nil {
				continue
			}
			switch buf[1] {
			case msgPunchPkt:
				fmt.Printf("cs2 dbg rx msgPunchPkt from %s, echoing punch and sending msgP2PRdyUDP\n", from)
				uc.addr = from
				_, _ = uc.Write(punch)
				_, _ = uc.Write([]byte{magic, msgP2PRdyUDP, 0x00, 0x00})
			case msgP2PRdyUDP:
				fmt.Printf("cs2 dbg direct punch SUCCESS from %s\n", from)
				return finish(from)
			case 0x81:
				fmt.Printf("cs2 dbg rx 0x81 ACK from %s\n", from)
				if sessAddr != nil && p83Sess != nil {
					uc.addr = sessAddr
					for i := 0; i < 8; i++ {
						_, _ = uc.Write(p83Sess)
					}
				}
			case msgMediaPunchAck, 0x28:
				if sessFrom == nil {
					sessFrom = from
					sessExpiry = time.Now().Add(1200 * time.Millisecond)
					fmt.Printf("cs2 dbg rx mediaPunchAck/0x28 from %s, setting 1.2s direct punch window (%d cam addrs)\n", from, len(camPubs))
					sweepCam()
				}
				if buf[1] == 0x28 && n >= 52 && buf[5] == 0x02 {
					peerPort := binary.LittleEndian.Uint16(buf[46:48])
					peerIP := net.IPv4(buf[51], buf[50], buf[49], buf[48])
					if !peerIP.IsPrivate() && !peerIP.IsLoopback() && peerIP.To4() != nil && peerPort != 0 {
						peerAddr := &net.UDPAddr{IP: peerIP, Port: int(peerPort)}
						fmt.Printf("cs2 dbg 0x28 peer addr: %s, sweeping punches\n", peerAddr)
						for dp := -3; dp <= 3; dp++ {
							uc.addr = &net.UDPAddr{IP: peerIP, Port: int(peerPort) + dp}
							_, _ = uc.Write(punch)
						}
					}
				}
				if buf[1] == 0x28 && n >= 6 {
					echo := make([]byte, n)
					copy(echo, buf[:n])
					echo[5] = 0x02
					if n >= 64 {
						copy(echo[60:64], []byte{0xfe, 0xff, 0xff, 0xff})
					}
					if n >= 84 && localPort != 0 && localIP != nil {
						echo[68], echo[69] = 0x00, 0x02
						binary.LittleEndian.PutUint16(echo[70:72], localPort)
						if v4 := localIP.To4(); v4 != nil {
							echo[72], echo[73], echo[74], echo[75] = v4[3], v4[2], v4[1], v4[0]
						}
					}
					uc.addr = sessFrom
					_, _ = uc.Write(echo)
				}
			}
			if sessFrom != nil && time.Now().After(sessExpiry) {
				break
			}
		}
		if sessFrom != nil {
			fmt.Printf("cs2 dbg relay-media SUCCESS, sessFrom=%s\n", sessFrom)
			return finish(sessFrom)
		}
		fmt.Printf("cs2 cloud: relay-media session failed (tokens=%d got73=%v relays=%d)\n", len(mediaToks), got73, len(relaySeen))
	}

	// ---- Phase D: legacy direct punch (punchable cameras) — but keep
	// collecting 0x82 handoffs meanwhile; the camera may only register
	// with relay-media seconds after waking. ----
	uc.addr = camAddr
	_ = uc.UDPConn.SetReadDeadline(time.Time{})
	_ = udp.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err = uc.Write(reqF9); err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("cs2 cloud: send 0xF9: %w", err)
	}
	sweepCam()
	directOK := false
	p2 := time.Now().Add(4 * time.Second)
	var lastPunch time.Time
	for time.Now().Before(p2) {
		if time.Since(lastPunch) > 500*time.Millisecond {
			sweepCam()
			lastPunch = time.Now()
		}
		_ = uc.UDPConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := uc.UDPConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			break
		}
		collect(n)
		if n >= 4 && buf[0] == magic {
			if buf[1] == msgPunchPkt {
				fmt.Printf("cs2 dbg phase D rx msgPunchPkt, echoing punch\n")
				uc.addr = camAddr
				_, _ = uc.Write(punch)
				_, _ = uc.Write([]byte{magic, msgP2PRdyUDP, 0x00, 0x00})
			} else if buf[1] == msgP2PRdyUDP {
				directOK = true
				break
			}
		}
	}
	if directOK {
		return finish(uc.addr)
	}

	// ---- Phase F: legacy punch through the relay (proven path for punchable
	// cameras) — falls through to the relay-media handoff on failure ----
	uc.addr = &net.UDPAddr{IP: net.ParseIP(relayHost), Port: 32100}
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	relayOK := false
	if _, err = uc.Write(reqF9); err == nil {
		res2, perr := uc.WriteUntil(punch, func(res []byte) bool {
			return res[1] == msgP2PRdyUDP || res[1] == msgPunchPkt
		})
		if perr == nil {
			if res2[1] == msgPunchPkt {
				_, err = uc.WriteUntil(res2, func(res []byte) bool {
					return res[1] == msgP2PRdyUDP
				})
				relayOK = err == nil
			} else {
				relayOK = true
			}
		}
	}
	if relayOK {
		return finish(uc.addr)
	}
	fmt.Printf("cs2 cloud: relay punch failed, trying relay-media handoff\n")

	_ = udp.Close()
	return nil, fmt.Errorf("cs2 cloud: all punch paths failed")
}

type Conn struct {
	net.Conn
	isTCP bool

	err    error
	seqCh0 uint16
	seqCh3 uint16

	channels [4]*dataChannel

	cmdMu     sync.Mutex
	cmdAck    atomic.Pointer[commandAck]
	closeOnce sync.Once
	closeErr  error
}

type handoffTok struct {
	addr  *net.UDPAddr
	token [4]byte
}

const (
	magic            = 0xF1
	magicDrw         = 0xD1
	magicTCP         = 0x68
	msgCloudConnect  = 0x20 // cs2 cloud-relay: client -> relay, session request via p2p_id
	msgCloudAck      = 0x21 // cs2 cloud-relay: relay -> client, ACK for 0x20
	msgLanSearch     = 0x30
	msgNatPunch      = 0x40 // cs2 cloud-relay: relay -> peer, NAT-punch addresses
	msgPunchPkt      = 0x41
	msgP2PRdyUDP     = 0x42
	msgP2PRdyTCP     = 0x43
	msgDrw           = 0xD0
	msgDrwAck        = 0xD1
	msgPing          = 0xE0
	msgPong          = 0xE1
	msgMediaProbeAck = 0x71
	msgMediaHandoff  = 0x82
	msgMediaPunch    = 0x83
	msgMediaPunchAck = 0x84
	msgClose         = 0xF0
	msgCloseAck      = 0xF1
	msgCloudAuth     = 0xF9 // cs2 cloud-relay: client -> relay, encrypted session auth
)

func handshake(host, transport string) (net.Conn, error) {
	conn, err := newUDPConn(host, 32108)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := []byte{magic, msgLanSearch, 0, 0}
	res, err := conn.(*udpConn).WriteUntil(req, func(res []byte) bool {
		return res[1] == msgPunchPkt
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	var msgUDP, msgTCP byte

	if transport == "" || transport == "udp" {
		msgUDP = msgP2PRdyUDP
	}
	if transport == "" || transport == "tcp" {
		msgTCP = msgP2PRdyTCP
	}

	res, err = conn.(*udpConn).WriteUntil(res, func(res []byte) bool {
		return res[1] == msgUDP || res[1] == msgTCP
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})

	if res[1] == msgTCP {
		_ = conn.Close()
		//host := fmt.Sprintf("%d.%d.%d.%d:%d", b[31], b[30], b[29], b[28], uint16(b[27])<<8|uint16(b[26]))
		return newTCPConn(conn.RemoteAddr().String())
	}

	return conn, nil
}

func (c *Conn) worker() {
	udpDone := make(chan struct{})
	var udpWG sync.WaitGroup
	defer func() {
		close(udpDone)
		udpWG.Wait()
		// A failed reader must free the camera's session before reconnecting.
		// Otherwise streams.reconnect keeps this socket until a replacement
		// login succeeds, which can be refused while the old peer still exists.
		_ = c.Close()
		c.channels[0].Close()
		c.channels[2].Close()
	}()

	// UDP keepalive: NAT mappings and relay sessions expire without traffic.
	// Cameras pause output for IDR gaps and hiccups; without a periodic ping
	// the relay drops the mapping and the next read times out (seen on the
	// Billing camera). The official app pings roughly every second on TCP;
	// the captured UDP app traffic also pings about once a second. Keep this
	// shorter than the five-second media read deadline.
	var mediaAcks *mediaAckBatch
	if !c.isTCP {
		mediaAcks = &mediaAckBatch{writer: c.Conn}
		udpWG.Add(1)
		go func() {
			defer udpWG.Done()
			t := time.NewTicker(time.Second)
			defer t.Stop()
			ackTick := time.NewTicker(20 * time.Millisecond)
			defer ackTick.Stop()
			for {
				select {
				case <-udpDone:
					_ = mediaAcks.Flush()
					return
				case <-ackTick.C:
					if err := mediaAcks.Flush(); err != nil {
						fmt.Printf("cs2: media acknowledgement failed: %v\n", err)
						_ = c.Conn.Close()
						return
					}
				case <-t.C:
					_, _ = c.Conn.Write([]byte{magic, msgPing, 0, 0})
				}
			}
		}()
	}

	var keepaliveTS time.Time // only for TCP
	statAt := time.Now()

	buf := make([]byte, 1200)

	for {
		if v := c.channels[2]; v != nil && time.Since(statAt) >= 10*time.Second {
			statAt = time.Now()
			srcs := ""
			if u, ok := c.Conn.(*udpConn); ok {
				srcs = u.takeSources()
			}
			fmt.Printf("cs2 stats %s video: inorder=%d dup=%d ahead=%d full=%d acks=%d maxgap=%d buffered=%d from:%s\n",
				c.Conn.RemoteAddr(), v.statInOrder, v.statDup, v.statAhead, v.statFull, v.statAcks, v.statMaxGap, len(v.pushBuf), srcs)
			v.statInOrder, v.statDup, v.statAhead, v.statFull, v.statAcks, v.statMaxGap = 0, 0, 0, 0, 0, 0
		}
		n, err := c.Conn.Read(buf)
		if err != nil {
			c.err = fmt.Errorf("%s: %w", "cs2", err)
			return
		}
		if n < 4 || buf[0] != magic {
			continue
		}

		// 0  f1d0  magic
		// 2  005d  size = total size + 4
		// 4  d1    magic
		// 5  00    channel
		// 6  0000  seq
		switch buf[1] {
		case msgDrw:
			if n < 8 || int(buf[5]) >= len(c.channels) || c.channels[buf[5]] == nil {
				c.err = fmt.Errorf("cs2: invalid data channel header")
				return
			}
			ch := buf[5]
			channel := c.channels[ch]

			if c.isTCP {
				// For TCP we should send ping every second to keep connection alive.
				// Based on PCAP analysis: official Mi Home app sends PING every ~1s.
				if now := time.Now(); now.After(keepaliveTS) {
					_, _ = c.Conn.Write([]byte{magic, msgPing, 0, 0})
					keepaliveTS = now.Add(time.Second)
				}

				err = channel.Push(buf[8:n])
			} else {
				var pushed int

				seqHI, seqLO := buf[6], buf[7]
				seq := uint16(seqHI)<<8 | uint16(seqLO)
				pushed, err = channel.PushSeq(seq, buf[8:n])

				if pushed >= 0 {
					channel.statAcks++
					// Xiaomi groups up to 17 CH2 sequences, flushing within
					// about 20ms. Keep CH0 immediate for command latency.
					if ch == 2 {
						err = mediaAcks.Add(seq)
					} else {
						ack := []byte{magic, msgDrwAck, 0, 6, magicDrw, ch, 0, 1, seqHI, seqLO}
						_, err = c.Conn.Write(ack)
					}
				}
			}

			if err != nil {
				c.err = fmt.Errorf("%s: %w", "cs2", err)
				return
			}

		case msgPing:
			_, _ = c.Conn.Write([]byte{magic, msgPong, 0, 0})
		case 0x28:
			if n >= 6 {
				echo := make([]byte, n)
				copy(echo, buf[:n])
				echo[5] = 0x02
				if n >= 64 {
					copy(echo[60:64], []byte{0xfe, 0xff, 0xff, 0xff})
				}
				if n >= 84 {
					if u, ok := c.Conn.LocalAddr().(*net.UDPAddr); ok && u != nil {
						echo[68], echo[69] = 0x00, 0x02
						binary.LittleEndian.PutUint16(echo[70:72], uint16(u.Port))
						lip := u.IP
						if lip == nil || lip.IsUnspecified() {
							lip = detectOutboundIP("34.100.251.170")
						}
						if lip != nil {
							if v4 := lip.To4(); v4 != nil {
								echo[72], echo[73], echo[74], echo[75] = v4[3], v4[2], v4[1], v4[0]
							}
						}
					}
				}
				_, _ = c.Conn.Write(echo)
			}
		case msgClose:
			_, _ = c.Conn.Write([]byte{magic, msgCloseAck, 0, 0})
			c.err = io.EOF
			_ = c.close(false)
			return
		case msgPong, msgP2PRdyUDP, msgP2PRdyTCP, msgCloseAck, msgMediaPunch, msgMediaPunchAck, msgMediaProbeAck, msgMediaHandoff, 0x81, 0x69: // skip it
		case msgDrwAck: // only for UDP
			c.acknowledgeCommand(buf[:n])
		default:
			fmt.Printf("cs2: unknown message type=%02x length=%d\n", buf[1], n)
		}
	}
}

func (c *Conn) Protocol() string {
	if c.isTCP {
		return "cs2+tcp"
	}
	return "cs2+udp"
}

// Close releases the remote CS2 session, not just the local UDP socket.
// Xiaomi Home sends F1 F0 on exit. Without it the camera can retain a ghost
// peer and reject the next authentication attempt with code 3.
func (c *Conn) Close() error { return c.close(true) }

func (c *Conn) close(notify bool) error {
	c.closeOnce.Do(func() {
		if notify {
			// A media read timeout may also have expired SetDeadline's write
			// deadline. Give the close datagram its own small bounded window.
			_ = c.Conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = c.Conn.Write([]byte{magic, msgClose, 0, 0})
		}
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *Conn) Version() string {
	return "CS2"
}

func (c *Conn) Error() error {
	if c.err != nil {
		return c.err
	}
	return io.EOF
}

func (c *Conn) ReadCommand() (cmd uint32, data []byte, err error) {
	buf, ok := c.channels[0].Pop()
	if !ok {
		return 0, nil, c.Error()
	}
	cmd = binary.LittleEndian.Uint32(buf)
	data = buf[4:]
	return
}

func (c *Conn) WriteCommand(cmd uint32, data []byte) error {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	seq := c.seqCh0
	req := marshalCmd(0, seq, cmd, data)
	c.seqCh0++

	if c.isTCP {
		_, err := c.Conn.Write(req)
		return err
	}

	ack := &commandAck{seq: seq, done: make(chan struct{})}
	c.cmdAck.Store(ack)
	defer c.cmdAck.CompareAndSwap(ack, nil)
	timeout := time.NewTicker(time.Second)
	defer timeout.Stop()
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := c.Conn.Write(req); err != nil {
			return err
		}
		select {
		case <-ack.done:
			return nil
		case <-timeout.C:
		}
	}
	return fmt.Errorf("cs2: can't send command %d", cmd)
}

type commandAck struct {
	seq  uint16
	done chan struct{}
	once sync.Once
}

func (c *Conn) acknowledgeCommand(b []byte) {
	if len(b) < 10 || b[4] != magicDrw || b[5] != 0 {
		return
	}
	ack := c.cmdAck.Load()
	if ack == nil {
		return
	}
	count := int(binary.BigEndian.Uint16(b[6:8]))
	if 8+count*2 > len(b) {
		return
	}
	for i := 0; i < count; i++ {
		if binary.BigEndian.Uint16(b[8+2*i:]) == ack.seq {
			ack.once.Do(func() { close(ack.done) })
			return
		}
	}
}

type mediaAckBatch struct {
	writer io.Writer
	mu     sync.Mutex
	seqs   []uint16
}

func (a *mediaAckBatch) Add(seq uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seqs = append(a.seqs, seq)
	if len(a.seqs) >= 17 {
		return a.flush()
	}
	return nil
}

func (a *mediaAckBatch) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flush()
}

func (a *mediaAckBatch) flush() error {
	if len(a.seqs) == 0 {
		return nil
	}
	b := make([]byte, 8+2*len(a.seqs))
	b[0], b[1], b[4], b[5] = magic, msgDrwAck, magicDrw, 2
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-4))
	binary.BigEndian.PutUint16(b[6:8], uint16(len(a.seqs)))
	for i, seq := range a.seqs {
		binary.BigEndian.PutUint16(b[8+2*i:], seq)
	}
	if _, err := a.writer.Write(b); err != nil {
		return err
	}
	a.seqs = a.seqs[:0]
	return nil
}

const hdrSize = 32

func (c *Conn) ReadPacket() (hdr, payload []byte, err error) {
	data, ok := c.channels[2].Pop()
	if !ok {
		return nil, nil, c.Error()
	}
	return data[:hdrSize], data[hdrSize:], nil
}

func (c *Conn) WritePacket(hdr, payload []byte) error {
	const offset = 12

	n := hdrSize + uint32(len(payload))
	req := make([]byte, n+offset)
	req[0] = magic
	req[1] = msgDrw
	binary.BigEndian.PutUint16(req[2:], uint16(n+8))

	req[4] = magicDrw
	req[5] = 3 // channel
	binary.BigEndian.PutUint16(req[6:], c.seqCh3)
	c.seqCh3++
	binary.BigEndian.PutUint32(req[8:], n)
	copy(req[offset:], hdr)
	copy(req[offset+hdrSize:], hdr)

	_, err := c.Conn.Write(req)
	return err
}

func marshalCmd(channel byte, seq uint16, cmd uint32, payload []byte) []byte {
	size := len(payload)
	req := make([]byte, 4+4+4+4+size)

	// 1. message header (4 bytes)
	req[0] = magic
	req[1] = msgDrw
	binary.BigEndian.PutUint16(req[2:], uint16(4+4+4+size))

	// 2. drw? header (4 bytes)
	req[4] = magicDrw
	req[5] = channel
	binary.BigEndian.PutUint16(req[6:], seq)

	// 3. payload size (4 bytes)
	binary.BigEndian.PutUint32(req[8:], uint32(4+size))

	// 4. payload command (4 bytes)
	binary.BigEndian.PutUint32(req[12:], cmd)

	// 5. payload
	copy(req[16:], payload)

	return req
}

func newUDPConn(host string, port int) (net.Conn, error) {
	// We using raw net.UDPConn, because RemoteAddr should be changed during handshake.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		addr = &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	}

	return &udpConn{UDPConn: conn, addr: addr}, nil
}

type udpConn struct {
	*net.UDPConn
	addr *net.UDPAddr

	// Data packets per source address since the last stats line.
	srcMu sync.Mutex
	srcs  map[string]int
}

// takeSources returns "addr=count ..." for the packets read since the last
// call, and resets the counts.
func (c *udpConn) takeSources() string {
	c.srcMu.Lock()
	defer c.srcMu.Unlock()
	out := ""
	for k, v := range c.srcs {
		out += fmt.Sprintf(" %s=%d", k, v)
	}
	c.srcs = nil
	return out
}

func (c *udpConn) Read(b []byte) (n int, err error) {
	var addr *net.UDPAddr
	for {
		n, addr, err = c.UDPConn.ReadFromUDP(b)
		if err != nil {
			return 0, err
		}
		if n >= 8 && b[1] == msgDrw {
			c.srcMu.Lock()
			if c.srcs == nil {
				c.srcs = map[string]int{}
			}
			key := addr.String()
			if key == c.addr.String() {
				key = "peer"
			}
			c.srcs[key]++
			c.srcMu.Unlock()
		}

		if string(addr.IP) == string(c.addr.IP) || n >= 8 {
			//log.Printf("<- %x", b[:n])
			return
		}
	}
}

func (c *udpConn) Write(b []byte) (n int, err error) {
	//log.Printf("-> %x", b)
	return c.UDPConn.WriteToUDP(b, c.addr)
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *udpConn) WriteUntil(req []byte, ok func(res []byte) bool) ([]byte, error) {
	var t *time.Timer
	t = time.AfterFunc(1, func() {
		if _, err := c.Write(req); err == nil && t != nil {
			t.Reset(time.Second)
		}
	})
	defer t.Stop()

	buf := make([]byte, 1200)

	for {
		n, addr, err := c.UDPConn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}

		if string(addr.IP) != string(c.addr.IP) || n < 16 {
			continue // skip messages from another IP
		}

		if ok(buf[:n]) {
			c.addr.Port = addr.Port
			return buf[:n], nil
		}
	}
}

func newTCPConn(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	return &tcpConn{conn.(*net.TCPConn), bufio.NewReader(conn)}, nil
}

type tcpConn struct {
	*net.TCPConn
	rd *bufio.Reader
}

func (c *tcpConn) Read(p []byte) (n int, err error) {
	tmp := make([]byte, 8)
	if _, err = io.ReadFull(c.rd, tmp); err != nil {
		return
	}
	n = int(binary.BigEndian.Uint16(tmp))
	if len(p) < n {
		return 0, fmt.Errorf("tcp: buffer too small")
	}
	_, err = io.ReadFull(c.rd, p[:n])
	//log.Printf("<- %x%x", tmp, p[:n])
	return
}

func (c *tcpConn) Write(req []byte) (n int, err error) {
	n = len(req)
	buf := make([]byte, 8+n)
	binary.BigEndian.PutUint16(buf, uint16(n))
	buf[2] = magicTCP
	copy(buf[8:], req)
	//log.Printf("-> %x", buf)
	_, err = c.TCPConn.Write(buf)
	return
}

func newDataChannel(pushSize, popSize int) *dataChannel {
	c := &dataChannel{}
	if pushSize > 0 {
		c.pushBuf = make(map[uint16][]byte, pushSize)
		c.pushSize = pushSize
	}
	if popSize >= 0 {
		c.popBuf = make(chan []byte, popSize)
	}
	return c
}

type dataChannel struct {
	waitSeq  uint16
	pushBuf  map[uint16][]byte
	pushSize int

	// Receive statistics for the session log (video channel).
	statInOrder, statDup, statAhead, statFull, statAcks int64
	statMaxGap                                          int

	waitData []byte
	waitSize int
	popBuf   chan []byte
	dropped  int
}

func (c *dataChannel) Push(b []byte) error {
	c.waitData = append(c.waitData, b...)

	for len(c.waitData) > 4 {
		// Every new data starts with size. There can be several data inside one packet.
		if c.waitSize == 0 {
			c.waitSize = int(binary.BigEndian.Uint32(c.waitData))
			c.waitData = c.waitData[4:]
		}
		if c.waitSize > len(c.waitData) {
			break
		}

		select {
		case c.popBuf <- c.waitData[:c.waitSize]:
		default:
			// A reader that stalls for a moment (a viewer that stopped
			// reading, or the burst when the camera moves) used to end the
			// camera connection for every viewer. Drop this packet instead;
			// the decoder recovers at the next keyframe.
			c.dropped++
			if c.dropped == 1 || c.dropped%500 == 0 {
				fmt.Printf("cs2: pop buffer full, dropped %d packets\n", c.dropped)
			}
		}

		c.waitData = c.waitData[c.waitSize:]
		c.waitSize = 0
	}
	return nil
}

func (c *dataChannel) Pop() ([]byte, bool) {
	data, ok := <-c.popBuf
	return data, ok
}

func (c *dataChannel) Close() {
	close(c.popBuf)
}

// PushSeq returns how many seq were processed.
// Returns 0 if seq was saved or processed earlier.
// Returns -1 if seq could not be saved (buffer full or disabled).
func (c *dataChannel) PushSeq(seq uint16, data []byte) (int, error) {
	diff := int16(seq - c.waitSeq)
	// Check if this is seq from the future.
	if diff > 0 {
		if int(diff) > c.statMaxGap {
			c.statMaxGap = int(diff)
		}
		// Support disabled buffer.
		if c.pushSize == 0 {
			c.statFull++
			return -1, nil // couldn't save seq
		}
		// Check if we don't have this seq in the buffer.
		if c.pushBuf[seq] == nil {
			// Check if there is enough space in the buffer.
			if len(c.pushBuf) == c.pushSize {
				c.statFull++
				return -1, nil // couldn't save seq
			}
			c.pushBuf[seq] = bytes.Clone(data)
			c.statAhead++
			//log.Printf("push buf wait=%d seq=%d len=%d", c.waitSeq, seq, len(c.pushBuf))
		}
		return 0, nil
	}

	// Check if this is seq from the past.
	if diff < 0 {
		c.statDup++
		return 0, nil
	}
	c.statInOrder++

	for i := 1; ; i++ {
		if err := c.Push(data); err != nil {
			return i, err
		}
		c.waitSeq++
		// Check if we have next seq in the buffer.
		if data = c.pushBuf[c.waitSeq]; data != nil {
			delete(c.pushBuf, c.waitSeq)
		} else {
			return i, nil
		}
	}
}
