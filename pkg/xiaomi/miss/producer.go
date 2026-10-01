package miss

import (
	"fmt"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/AlexxIT/go2rtc/pkg/h265"
	"github.com/pion/rtp"
)

type Producer struct {
	core.Connection
	client *Client
	// did/subtype for log lines, and when the session opened.
	tag    string
	opened time.Time
	// Packets probe() read from the first keyframe on, sent before live ones.
	pending []*Packet
}

// A session whose video stops this long (even with audio flowing) ends.
const videoStall = 6 * time.Second

func sessionTag(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "?"
	}
	q := u.Query()
	sub := q.Get("subtype")
	if sub == "" {
		sub = "auto"
	}
	return "did=" + q.Get("did") + " sub=" + sub
}

func slog(tag, msg string) {
	fmt.Printf("%s miss session %s %s\n", time.Now().Format("15:04:05.000"), tag, msg)
}

func Dial(rawURL string) (core.Producer, error) {
	start := time.Now()
	tag := sessionTag(rawURL)
	client, err := NewClient(rawURL)
	if err != nil {
		slog(tag, fmt.Sprintf("connect failed after %dms: %v", time.Since(start).Milliseconds(), err))
		return nil, err
	}

	u, _ := url.Parse(rawURL)
	query := u.Query()

	// subtype=upgrade: one session that opens at 360p (the camera answers
	// in ~1 s) and switches itself to HD once the stream is set up, so the
	// viewer gets a picture at once and HD in the same stream, like Xiaomi
	// Home. HD opened directly takes 4-8 s before the first picture.
	sub := query.Get("subtype")
	upgrade := sub == "upgrade"
	if upgrade {
		sub = "sd"
	}
	connected := time.Since(start).Milliseconds()
	err = client.StartMedia(query.Get("channel"), sub, query.Get("audio"))
	if err != nil {
		slog(tag, fmt.Sprintf("start media failed: %v", err))
		_ = client.Close()
		return nil, err
	}
	started := time.Since(start).Milliseconds()

	medias, pending, err := probe(client, query.Get("audio") != "0", tag, start)
	if err != nil {
		slog(tag, fmt.Sprintf("probe failed after %dms: %v", time.Since(start).Milliseconds(), err))
		_ = client.Close()
		return nil, err
	}
	if upgrade {
		if err := client.StartMedia(query.Get("channel"), "hd", query.Get("audio")); err != nil {
			slog(tag, fmt.Sprintf("upgrade to hd failed: %v", err))
		} else {
			slog(tag, fmt.Sprintf("upgrade to hd after %dms", time.Since(start).Milliseconds()))
		}
	}
	slog(tag, fmt.Sprintf("open in %dms via %s (transport %dms, login %dms, connected %dms, media started %dms)",
		time.Since(start).Milliseconds(), client.Protocol(), client.DialMs, client.LoginMs, connected, started))

	return &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "xiaomi/miss",
			Protocol:   client.Protocol(),
			RemoteAddr: client.RemoteAddr().String(),
			UserAgent:  client.Version(),
			Medias:     medias,
			Transport:  client,
		},
		client:  client,
		pending: pending,
		tag:     tag,
		opened:  time.Now(),
	}, nil
}

func probe(client *Client, audio bool, tag string, start time.Time) ([]*core.Media, []*Packet, error) {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	var vcodec, acodec *core.Codec
	var pending []*Packet
	var pendingSince time.Time
	var seenAny, seenVideo bool

	for {
		pkt, err := client.ReadPacket()
		if err != nil {
			if vcodec != nil {
				err = fmt.Errorf("no audio")
			} else if acodec != nil {
				err = fmt.Errorf("no video")
			}
			return nil, nil, fmt.Errorf("xiaomi: probe: %w", err)
		}

		if !seenAny {
			seenAny = true
			slog(tag, fmt.Sprintf("first packet at %dms", time.Since(start).Milliseconds()))
		}
		if !seenVideo && (pkt.CodecID == codecH264 || pkt.CodecID == codecH265) {
			seenVideo = true
			slog(tag, fmt.Sprintf("first video at %dms", time.Since(start).Milliseconds()))
		}
		switch pkt.CodecID {
		case codecH264:
			if vcodec == nil {
				buf := annexb.EncodeToAVCC(pkt.Payload)
				if h264.NALUType(buf) == h264.NALUTypeSPS {
					vcodec = h264.AVCCToCodec(buf)
				}
			}
		case codecH265:
			if vcodec == nil {
				buf := annexb.EncodeToAVCC(pkt.Payload)
				if h265.NALUType(buf) == h265.NALUTypeVPS {
					vcodec = h265.AVCCToCodec(buf)
				}
			}
		case codecPCMA:
			if acodec == nil {
				acodec = &core.Codec{Name: core.CodecPCMA, ClockRate: pkt.SampleRate()}
			}
		case codecOPUS:
			if acodec == nil {
				acodec = &core.Codec{Name: core.CodecOpus, ClockRate: 48000, Channels: 2}
			}
		}

		if vcodec != nil {
			if pending == nil {
				pendingSince = time.Now()
				slog(tag, fmt.Sprintf("keyframe at %dms", time.Since(start).Milliseconds()))
			}
			pending = append(pending, pkt)
		}
		if vcodec != nil && (acodec != nil || !audio) {
			break
		}
	}

	_ = client.SetDeadline(time.Time{})

	medias := []*core.Media{
		{
			Kind:      core.KindVideo,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{vcodec},
		},
	}

	if acodec != nil {
		medias = append(medias, &core.Media{
			Kind:      core.KindAudio,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{acodec},
		})

		medias = append(medias, &core.Media{
			Kind:      core.KindAudio,
			Direction: core.DirectionSendonly,
			Codecs:    []*core.Codec{acodec.Clone()},
		})
	}

	// Without its keyframe the viewer waits for the camera's next one (3-6 s).
	// Players that keep to the live edge (a low-latency player drains it fast) lose
	// nothing; a keyframe older than 3 s is dropped all the same.
	if time.Since(pendingSince) > 3*time.Second {
		pending = nil
	}
	return medias, pending, nil
}

const timestamp40ms = 48000 * 0.040

func (p *Producer) Start() (err error) {
	// Release this camera session before streams.reconnect dials a replacement,
	// including video-only stalls where the UDP reader itself is still alive.
	defer func() { _ = p.client.Close() }()
	var audioTS uint32
	lastVideo := time.Now()
	// mediaWatch: the read deadline sits on the UDP socket, and CS2 keepalive
	// packets keep refreshing it. Billing stopped sending media but kept
	// answering keepalives; ReadPacket then waited forever and every viewer
	// hung. Close the session when no media packet arrives for 8 s.
	var lastPkt atomic.Int64
	lastPkt.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastPkt.Load())) > 8*time.Second {
					slog(p.tag, "no media for 8s (keepalives only): closing")
					_ = p.client.Close()
					return
				}
			}
		}
	}()
	defer func() {
		slog(p.tag, fmt.Sprintf("ended after %s, %d KB: %v",
			time.Since(p.opened).Round(time.Second), p.Recv/1024, err))
	}()

	pending := p.pending
	p.pending = nil
	var gop gopCache
	for {
		var pkt *Packet
		if len(pending) > 0 {
			pkt, pending = pending[0], pending[1:]
		} else {
			_ = p.client.SetDeadline(time.Now().Add(5 * time.Second))
			pkt, err = p.client.ReadPacket()
			if err != nil {
				return err
			}
		}
		lastPkt.Store(time.Now().UnixNano())
		if pkt.CodecID == codecH264 || pkt.CodecID == codecH265 {
			lastVideo = time.Now()

		} else if time.Since(lastVideo) > videoStall {
			return fmt.Errorf("video stopped %s ago while audio still flows", time.Since(lastVideo).Round(time.Second))
		}

		p.Recv += len(pkt.Payload)

		// TODO: rewrite this
		var name string
		var pkt2 *core.Packet

		switch pkt.CodecID {
		case codecH264, codecH265:
			pkt2 = &core.Packet{
				Header: rtp.Header{
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      TimeToRTP(pkt.Timestamp, 90000),
				},
				Payload: annexb.EncodeToAVCC(pkt.Payload),
			}
			if pkt.CodecID == codecH264 {
				name = core.CodecH264
			} else {
				name = core.CodecH265
			}
		case codecPCMA:
			name = core.CodecPCMA
			pkt2 = &core.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      audioTS,
				},
				Payload: pkt.Payload,
			}
			audioTS += uint32(len(pkt.Payload))
		case codecOPUS:
			name = core.CodecOpus
			pkt2 = &core.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      audioTS,
				},
				Payload: pkt.Payload,
			}
			// known cameras sends packets with 40ms long
			audioTS += timestamp40ms
		}

		for _, recv := range p.Receivers {
			if recv.Codec.Name == name {
				switch name {
				case core.CodecH264:
					gop.write(recv, pkt2, h264.IsKeyframe(pkt2.Payload))
				case core.CodecH265:
					gop.write(recv, pkt2, h265.IsKeyframe(pkt2.Payload))
				default:
					recv.WriteRTP(pkt2)
				}
				break
			}
		}
	}
}

// gopCache gives a viewer joining a running stream the frames since the
// last keyframe at once. Without it the viewer's decoder waits for the
// camera's next keyframe (every 6 s on HD, 3-5 s on 360p) and then starts
// that far behind. Xiaomi Home opens its own camera session, which starts
// on a keyframe; viewers sharing a session need the cache. The replayed
// frames keep their times: the player plays them out fast to live.
type gopCache struct {
	frames   []*core.Packet
	overflow bool
	seen     map[*core.Node]bool
}

// gopMax holds 6 s of 25 fps with room; a longer interval replays nothing
// rather than an incomplete run of frames.
const gopMax = 400

func (g *gopCache) write(recv *core.Receiver, pkt *core.Packet, keyframe bool) {
	if keyframe {
		g.frames = g.frames[:0]
		g.overflow = false
	}
	if !g.overflow && (keyframe || len(g.frames) > 0) {
		if len(g.frames) < gopMax {
			g.frames = append(g.frames, pkt)
		} else {
			g.frames = g.frames[:0]
			g.overflow = true
		}
	}
	childs := recv.Node.Childs()
	seen := make(map[*core.Node]bool, len(childs))
	for _, c := range childs {
		// A new viewer, not starting on a keyframe anyway.
		if !g.seen[c] && g.seen != nil && !keyframe && len(g.frames) > 1 {
			for _, f := range g.frames[:len(g.frames)-1] {
				c.Input(f)
			}
		}
		seen[c] = true
	}
	g.seen = seen
	recv.WriteRTP(pkt)
}

func (p *Producer) Stop() error {
	// Xiaomi Home closes a CS2 session with F0; it does not send a separate
	// video-stop command. Some cameras apply that command to their encoder,
	// interrupting the HD session when a parallel SD preview is released.
	if p.client.Conn.Version() != "CS2" {
		_ = p.client.StopMedia()
	}
	return p.Connection.Stop()
}

// TimeToRTP convert time in milliseconds to RTP time
func TimeToRTP(timeMS, clockRate uint64) uint32 {
	return uint32(timeMS * clockRate / 1000)
}

// SetQuality switches the running session's quality (hd, sd, auto). The
// picture continues; the new quality starts at the camera's next keyframe.
func (p *Producer) SetQuality(q string) error {
	slog(p.tag, "quality -> "+q)
	return p.client.StartMedia("", q, "1")
}

// Motor moves a pan/tilt camera one step: left, right, up, down.
func (p *Producer) Motor(dir string) error {
	slog(p.tag, "motor "+dir)
	return p.client.Motor(dir)
}
