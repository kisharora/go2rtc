package miss

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/tutk"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/crypto"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/miss/cs2"
)

const (
	codecH264 = 4
	codecH265 = 5
	codecPCM  = 1024
	codecPCMU = 1026
	codecPCMA = 1027
	codecOPUS = 1032
)

type Conn interface {
	Protocol() string
	Version() string
	ReadCommand() (cmd uint32, data []byte, err error)
	WriteCommand(cmd uint32, data []byte) error
	ReadPacket() (hdr, payload []byte, err error)
	WritePacket(hdr, payload []byte) error
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	Close() error
}

func NewClient(rawURL string) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	// 1. Check if we can create shared key.
	query := u.Query()
	key, err := crypto.CalcSharedKey(query.Get("device_public"), query.Get("client_private"))
	if err != nil {
		return nil, err
	}

	model := query.Get("model")

	// 2. Check if this vendor supported.
	dialStart := time.Now()
	var conn Conn
	switch s := query.Get("vendor"); s {
	case "cs2":
		// If a p2p_id is present, the camera only reachable via the
		// Mi-Cloud relay (typical for MJA1-secure-element cameras such
		// as the c302n). Otherwise fall back to the direct LAN handshake.
		if p2pID := query.Get("p2p_id"); p2pID != "" {
			// One connection attempt, relays in turn (never in parallel).
			hosts := []string{u.Host}
			if alt := query.Get("relay_alt"); alt != "" {
				hosts = append(hosts, strings.Split(alt, ",")...)
			}
			for _, host := range hosts {
				if conn, err = cs2.DialCloud(p2pID, host); err == nil {
					break
				}
			}
		} else {
			conn, err = cs2.Dial(u.Host, query.Get("transport"))
		}
	case "tutk":
		conn, err = tutk.Dial(u.Host, query.Get("uid"), "Miss", "client")
	default:
		err = fmt.Errorf("miss: unsupported vendor %s", s)
	}

	if err != nil {
		return nil, err
	}

	dialMs := time.Since(dialStart).Milliseconds()
	err = login(conn, query.Get("client_public"), query.Get("sign"))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &Client{Conn: conn, key: key, model: model,
		DialMs: dialMs, LoginMs: time.Since(dialStart).Milliseconds() - dialMs}, nil
}

type Client struct {
	Conn
	key   []byte
	model string
	// Connect timing for the session log: transport (cs2/tutk) and login.
	DialMs, LoginMs int64
}

const (
	cmdAuthReq           = 0x100
	cmdAuthRes           = 0x101
	cmdVideoStart        = 0x102
	cmdVideoStop         = 0x103
	cmdAudioStart        = 0x104
	cmdAudioStop         = 0x105
	cmdSpeakerStartReq   = 0x106
	cmdSpeakerStartRes   = 0x107
	cmdSpeakerStop       = 0x108
	cmdStreamCtrlReq     = 0x109
	cmdStreamCtrlRes     = 0x10A
	cmdGetAudioFormatReq = 0x10B
	cmdGetAudioFormatRes = 0x10C
	cmdPlaybackReq       = 0x10D
	cmdPlaybackRes       = 0x10E
	cmdDevInfoReq        = 0x110
	cmdDevInfoRes        = 0x111
	cmdMotorReq          = 0x112
	cmdMotorRes          = 0x113
	cmdEncoded           = 0x1001
)

func login(conn Conn, clientPublic, sign string) error {
	// cloudHandshake clears its socket deadline. Without an auth deadline,
	// ReadCommand can wait forever while the stream's reconnect mutex is held,
	// preventing every subsequent viewer from opening that camera.
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return fmt.Errorf("miss: auth deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	s := fmt.Sprintf(`{"public_key":"%s","sign":"%s","uuid":"","support_encrypt":0}`, clientPublic, sign)
	if err := conn.WriteCommand(cmdAuthReq, []byte(s)); err != nil {
		return err
	}

	_, data, err := conn.ReadCommand()
	if err != nil {
		return err
	}

	if !bytes.Contains(data, []byte(`"result":"success"`)) {
		return fmt.Errorf("miss: auth: %s", data)
	}

	return nil
}

func (c *Client) Version() string {
	return fmt.Sprintf("%s (%s)", c.Conn.Version(), c.model)
}

func (c *Client) WriteCommand(data []byte) error {
	data, err := crypto.Encode(data, c.key)
	if err != nil {
		return err
	}
	return c.Conn.WriteCommand(cmdEncoded, data)
}

const (
	ModelDafang  = "isa.camera.df3"
	ModelLoockV2 = "loock.cateye.v02"
	ModelC200    = "chuangmi.camera.046c04"
	ModelC300    = "chuangmi.camera.72ac1"
	// ModelDinglingN1 ignores videoquality 2 entirely — it only starts the
	// media engine at quality 3 (2304x1296 HEVC). Same behaviour as C200/C300.
	ModelDinglingN1 = "xiaovv.camera.fjcam6"
	// ModelXiaofang looks like it has the same firmware as the ModelDafang.
	// There is also an older model "isa.camera.isc5" that only works with the legacy protocol.
	ModelXiaofang = "isa.camera.isc5c1"
)

func (c *Client) StartMedia(channel, quality, audio string) error {
	switch c.model {
	case ModelDafang, ModelXiaofang:
		var q, a byte
		if quality == "sd" {
			q = 1 // 0 - hd, 1 - sd, default - hd
		}
		if audio != "0" {
			a = 1 // 0 - off, 1 - on, default - on
		}

		return errors.Join(
			c.WriteCommand(dafangVideoQuality(q)),
			c.WriteCommand(dafangVideoStart(1, a)),
		)
	}

	// 0 - auto, 1 - sd, 2 - hd, default - hd
	switch quality {
	case "", "hd":
		// Some models have broken codec settings in quality 3.
		// Some models have low quality in quality 2.
		// Different models require different default quality settings.
		switch c.model {
		case ModelC200, ModelC300, ModelDinglingN1:
			quality = "3"
		default:
			quality = "2"
		}
	case "sd":
		quality = "1"
	case "auto":
		quality = "0"
	}

	if audio == "" {
		audio = "1"
	}

	data := binary.BigEndian.AppendUint32(nil, cmdVideoStart)
	switch channel {
	case "", "0":
		data = fmt.Appendf(data, `{"videoquality":%s,"enableaudio":%s}`, quality, audio)
	default:
		data = fmt.Appendf(data, `{"videoquality":-1,"videoquality2":%s,"enableaudio":%s}`, quality, audio)
	}
	if err := c.WriteCommand(data); err != nil {
		return err
	}
	return nil
}

// Motor sends one pan/tilt step, as Xiaomi Home does over the P2P session.
func (c *Client) Motor(dir string) error {
	op := map[string]int{"left": 1, "right": 2, "up": 3, "down": 4}[dir]
	if op == 0 {
		return fmt.Errorf("miss: motor: unknown direction %q", dir)
	}
	data := binary.BigEndian.AppendUint32(nil, cmdMotorReq)
	data = fmt.Appendf(data, `{"op":%d}`, op)
	return c.WriteCommand(data)
}

func (c *Client) StopMedia() error {
	data := binary.BigEndian.AppendUint32(nil, cmdVideoStop)
	return c.WriteCommand(data)
}

func (c *Client) StartAudio() error {
	data := binary.BigEndian.AppendUint32(nil, cmdAudioStart)
	return c.WriteCommand(data)
}

func (c *Client) StartSpeaker() error {
	data := binary.BigEndian.AppendUint32(nil, cmdSpeakerStartReq)
	return c.WriteCommand(data)
}

// SpeakerCodec if the camera model has a non-standard two-way codec.
func (c *Client) SpeakerCodec() uint32 {
	switch c.model {
	case ModelDafang, ModelXiaofang, "isa.camera.hlc6":
		return codecPCM
	case "chuangmi.camera.72ac1":
		return codecOPUS
	}
	return 0
}

const hdrSize = 32

func (c *Client) ReadPacket() (*Packet, error) {
	hdr, payload, err := c.Conn.ReadPacket()
	if err != nil {
		return nil, fmt.Errorf("miss: read media: %w", err)
	}

	if len(hdr) < hdrSize {
		return nil, fmt.Errorf("miss: packet header too small")
	}

	payload, err = crypto.Decode(payload, c.key)
	if err != nil {
		return nil, err
	}

	pkt := &Packet{
		CodecID:  binary.LittleEndian.Uint32(hdr[4:]),
		Sequence: binary.LittleEndian.Uint32(hdr[8:]),
		Flags:    binary.LittleEndian.Uint32(hdr[12:]),
		Payload:  payload,
	}

	switch c.model {
	case ModelDafang, ModelXiaofang, ModelLoockV2:
		// Dafang has ts in sec
		// LoockV2 has ts in msec for video, but zero ts for audio
		pkt.Timestamp = uint64(time.Now().UnixMilli())
	default:
		pkt.Timestamp = binary.LittleEndian.Uint64(hdr[16:])
	}

	return pkt, nil
}

func (c *Client) WriteAudio(codecID uint32, payload []byte) error {
	payload, err := crypto.Encode(payload, c.key) // new payload will have new size!
	if err != nil {
		return err
	}

	n := uint32(len(payload))

	header := make([]byte, hdrSize)
	binary.LittleEndian.PutUint32(header, n)
	binary.LittleEndian.PutUint32(header[4:], codecID)
	binary.LittleEndian.PutUint64(header[16:], uint64(time.Now().UnixMilli())) // not really necessary
	return c.Conn.WritePacket(header, payload)
}

type Packet struct {
	//Length    uint32
	CodecID   uint32
	Sequence  uint32
	Flags     uint32
	Timestamp uint64 // msec
	//TimestampS uint32
	//Reserved uint32
	Payload []byte
}

func (p *Packet) SampleRate() uint32 {
	// flag:         1 0011 000 - sample rate 16000
	// flag: 100 00 01 0000 000 - sample rate  8000
	v := (p.Flags >> 3) & 0b1111
	if v != 0 {
		return 16000
	}
	return 8000
}

//func (p *Packet) AudioUnknown1() byte {
//	return byte((p.Flags >> 7) & 0b11)
//}
//
//func (p *Packet) AudioUnknown2() byte {
//	return byte((p.Flags >> 9) & 0b11)
//}

func dafangRaw(cmd uint32, args ...byte) []byte {
	payload := tutk.ICAM(cmd, args...)

	data := make([]byte, 4+len(payload)*2)
	copy(data, "\x7f\xff\xff\xff")
	hex.Encode(data[4:], payload)
	return data
}

// DafangVideoQuality 0 - hd, 1 - sd
func dafangVideoQuality(quality uint8) []byte {
	return dafangRaw(0xff07d5, quality)
}

func dafangVideoStart(video, audio uint8) []byte {
	return dafangRaw(0xff07d8, video, audio)
}

//func dafangLeft() []byte {
//	return dafangRaw(0xff2404, 2, 0, 5)
//}
//
//func dafangRight() []byte {
//	return dafangRaw(0xff2404, 1, 0, 5)
//}
//
//func dafangUp() []byte {
//	return dafangRaw(0xff2404, 0, 2, 5)
//}
//
//func dafangDown() []byte {
//	return dafangRaw(0xff2404, 0, 1, 5)
//}
//
//func dafangStop() []byte {
//	return dafangRaw(0xff2404, 0, 0, 5)
//}
