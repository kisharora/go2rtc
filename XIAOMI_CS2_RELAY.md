# Xiaomi Mi Home "cs2" Cloud Relay Protocol (region i2) — Method Notes

Reverse-engineering notes for Xiaomi's native cloud relay used by Mi Home
cameras (vendor `cs2`). This is the protocol that the Mi Home app uses to
watch cameras in **full native resolution over the Xiaomi cloud** — including
when both the phone and the camera sit behind NAT.

This repository's `pkg/xiaomi/miss/cs2` implementation (based on
**glissmam's** go2rtc PR #2264 — all credit to him for the original cloud
relay handshake) plus the patches documented here make it work for the
India (`i2`) region, which the upstream code did not cover.

> **Ethics & legality**: everything below was captured from traffic generated
> by our own cameras and our own Mi Home account, on our own network, for
> personal interoperability with hardware we own. No Xiaomi credentials,
> tokens, or account data are published here. Please keep it that way.

## 1. Discovering the relay (miss_get_vendor)

When the Mi Home app opens a camera stream it asks the Miot cloud for the
camera's streaming vendor:

- RPC `miss_get_vendor` returns `vendor: cs2` plus a **`p2p_id`**.
- The `p2p_id` has the form `XMSYIN-XXXXXX-XXXXX` (`IN` = India region;
  the region code in the ID must match your account's region).
- The app then performs a UDP handshake against one of Xiaomi's relay IPs on
  **:32100** and — for hard-NAT cameras — a secondary relay-media pool on
  **:25000**.

Region i2 relay pools observed (may change over time — do not hardcode in
production, discover per session):

- Directory/relay :32100 — a small pool of GCP India IPs.
- Relay-media :25000 — a larger pool, used when the camera cannot be
  punched through directly.

## 2. UDP handshake (cloud relay)

Framing: every datagram starts with the 2-byte magic `f1 d0`, then a 1-byte
message type, then a big-endian 2-byte payload length, then the payload.

| Type   | Name        | Direction   | Purpose |
|--------|-------------|-------------|---------|
| 0x20   | CONNECT     | app → relay | contains an encrypted P2P-ID block (see §3) |
| 0xF9   | AUTH        | app → relay | encrypted auth blob, ties the session to the p2p_id |
| 0x21   | ACK         | relay → app | acknowledges CONNECT/AUTH |
| 0x40   | PUNCH INFO  | relay → app | camera's sockaddr (little-endian) + relay session info |
| 0x41   | PUNCH       | app → relay/cam | carries the p2p_id block to the camera |
| 0x42   | UDP READY   | relay → app | direct UDP media path established |
| 0x43   | TCP READY   | relay → app | fallback TCP media path established |
| 0xF0   | CLOSE       | either      | session teardown |

Handshake order observed: `CONNECT → ACK → AUTH → ACK → PUNCH INFO → PUNCH →
UDP/TCP READY → media`.

### 0xF9 AUTH details (i2 region fixes)

Upstream PR #2264 was authored against a different region. Two i2-specific
corrections (see `conn.go`, `buildCloudAuth`):

1. **Plaintext byte 23 must be `0x01`** (upstream used `0x06`).
2. **Bytes 28–29 carry a per-session sequence number** (big-endian), not the
   constant `0x0088`.

The payload is encrypted with the `SSD@cs2-network.` key schedule implemented
in `encryptP2P` (see upstream PR for the table).

3. **Relay discovery**: the hardcoded global relay host does not serve i2.
   The relay must be selected from the i2 pools (or discovered from the
   `miss_get_vendor` response / PCAP of the official app).

## 3. Media framing

- **TCP**: `msgDrw` frames carry per-channel data; the official app sends
  `PING` roughly every second and the relay answers `PONG`.
- **UDP**: every `msgDrw` carries a 2-byte sequence number (bytes 6–7) and
  must be acknowledged with `msgDrwAck` (`{magic, 0xDrwAck, 0, 6, magicDrw,
  ch, 0, 1, seq_hi, seq_lo}`).

### Keepalive gap (fixed in this fork)

Upstream only pings on TCP. On UDP, when a camera briefly stops emitting
frames (IDR gap, stream hiccup), no traffic flows, the NAT mapping / relay
session expires, and the next read times out
(`cs2: read udp i/o timeout`). This fork adds a **5-second UDP PING** that
runs for the lifetime of the connection, which eliminates those mid-view
drops.

## 4. Waking sleeping cameras

Mi Home cameras sleep aggressively. The reliable wake is minting an HLS
stream via the Miot cloud (`start_hls_stream`, siid 7 for `026c05`-class,
siid 4 for `ipc019`); the camera wakes to serve the (cloud) stream and stays
up long enough for the cs2 relay to connect. Alexa's `start_rtsp_stream`
(siid 8 / 3) works as an alternative but was less reliable in region i2.

## 5. Hard-NAT cameras: the relay-media handoff (region i2, WIP)

PCAP of the official app watching two hard-NAT cameras (CGNAT site) shows
the full handoff dance:

- Framing correction: datagrams are F1 | type | len_hi | len_lo | payload
  where LEN = payload length (not total). Media data is type 0xD0, ACKs
  0xD1 (f1 d1 0006 d1 ch seq:2), ping/pong 0xE0/0xE1, close 0xF0.
- After CONNECT (0x20) the app sends a 0x67 query: F1 67 00 14
  <p2p_id_block:16> 0000.
- The relay answers with the legacy 0x40 punch-info (camera LAN addr,
  little-endian) plus one or more 0x82 handoff messages: same layout,
  [6:8] port LE, [8:12] IP LE, pointing at a relay-media server on port
  25000 (34.47.210.148:25000 / 34.14.178.128:25000 seen).
- The app punches the relay-media server with 0x83: F1 83 001C <nonce:4>
  <p2p_id_block:16> 0000, repeated every ~150 ms. Relay-media answers 0x84
  (F1 84 0014 <p2p_id_block>) and re-sources the session onto an ephemeral
  server port (e.g. :29688); the client keeps answering that 5-tuple.
- During media the client repeats both a 0x28 session punch (92 B with a
  stable 16-byte session token: a1 ctr 0030 token16 p2p_id_block) and the
  0x83 punch, plus 0xD1 ACKs for every 0xD0 media frame.
- A control message carrying JSON ({"result":"success","channel":...})
  confirms session establishment.

Fork status: 0x82 parsing, the linger window past the first 0x40, and the
0x83 punch to the handoff address are implemented in conn.go. The relay
still did not emit 0x82 to our client in testing; the missing piece is the
camera-side registration trigger (the camera must join the relay-media pool
when woken; possibly the 0x80 message - F1 80 0028 <p2p_id_block> <pad4>
0002 <port LE> <ip LE> <zeros8> <nonce4> - is the client's relay-media
session request). Next session: replay the app sequence (0x20, 0x67, 0xF9,
0x80) against the relay with a woken camera and compare.



## 7. 0x20 sockaddr experiment — FALSIFIED, reverted (2026-09-07)

The 0x20 CONNECT payload's bytes 20-36 were suspected to need the client's
own UDP sockaddr (the app's capture shows 02 | port LE | ip-reversed there;
upstream puts a BE timestamp). A sockaddr variant was built and deployed —
and it **broke the handshake**: the relay stopped sending 0x01/0x40 entirely
for ALL cameras (punchable ones included), causing 25s timeouts and HLS
fallbacks. Reverted to the upstream timestamp form; the punchable-camera
path immediately returned to working state, with frames live to the second
(verified by reading the camera's own datetime overlay against wall clock).

Lesson recorded: the app's extra bytes may matter only to the app's TUTK
engine internals, or the field is a nonce — the upstream timestamp form is
what the relay accepts for the direct-punch path. The sockaddr layout
remains plausible for the relay-media handoff path specifically; retest
ONLY with a live handoff comparison against the app on the same relay.

## 8. Handoff status (open)

With 0x20 fixed, 0x67 after the first 0x40, and 0x83 punches implemented,
the relay STILL does not emit 0x82 to our client (the app receives it ~150 ms
after its first 0x67). Remaining hypotheses, in order:

1. The camera must have joined the relay-media pool for its session, which
   likely requires the cloud P2P-stream start (siid 6 / raw-stream
   registration) rather than an HLS-mint wake.
2. The 0x69 message (136 B, a list of relay-media endpoints returned after
   0x67) may need to be handled/acknowledged before handoff completes.
3. The 0x28 session punch (92 B with a stable 16-byte session token) may be
   required during the punch phase, not just during media.

Everything AFTER the first 0x82 is implemented and app-verified. The captures
and parser scripts used during reverse-engineering are not included here.


## 10. 0xF9 auth plaintext FULLY DECODED (2026-09-07, the crown jewel)

Decrypting the macOS app's 0xF9 (universal SSD@cs2-network cipher works —
verified: our Python port is byte-identical to the Go implementation) reveals
the complete 84-byte plaintext:

    [0:20]  p2p_id block (same as 0x20)
    [20:36] capability block, app-exact bytes (region i2):
            00 00 00 02 00 14 00 02 03 62 00 01 7a 00 00 00
            (matches the app's "MTP enabled connect types, LAN/WAN/RELAY"
            internal reporting — replicate verbatim)
    [36:52] LOCAL sockaddr:  0000 | port LE | ip reversed | zeros(8)
            app: family=0 port=<p> ip=<client LAN IP> (its real UDP socket!)
    [52:68] WAN sockaddr:    0000 | port LE | ip reversed | zeros(8)
            app: port=<p> ip=<client public/NAT IP> (its NAT public mapping!)
    [68:84] DEVICE sockaddr: 0000 | port LE | ip reversed | zeros(8)
            app: port=<p> ip=<relay-media IP> — THE RELAY-MEDIA ENDPOINT
            the app wants the camera bound to!!

THE MECHANISM: 0x67 queries the relay-media list (0x82/0x69); the app
punches relay-media and learns a concrete endpoint; the 0xF9 auth then
carries that endpoint in the DEVICE sockaddr — the relay connects the
camera to it. Our fork sends ZEROS in the device field, which is exactly
why the relay never hands off to us.

IMPLEMENTATION PLAN (next session):
1. 0xF9 plaintext: replace cloudAuthUnknownBlock with the app's capability
   bytes; fill local = our socket (port+LAN ip); wan = our PUBLIC mapping
   (learn via a STUN-style request or an IP-echo service); device = the
   relay-media endpoint (from 0x82 handoff: ip:25000, or the ephemeral
   port discovered by punching).
2. Sequence: 0x67 -> 0x82/0x69 -> punch relay-media -> 0xF9(device=endpoint)
   -> media.
3. Decrypt verification tool: /tmp/decrypt_f9.py (cipher port verified
   byte-identical against the Go implementation).
4. The p2p_id is session-rotating: `XMSYIN-XXXXXX-XXXXX` was one allocation;
   per-dial miss_get_vendor responses rotate (num/suffix change). The block
   transmitted must be the SAME session's id as the wake command used.

## 10. Reproducing

1. Build this fork (upstream PR #2264 + the i2 patches in `conn.go`).
2. Give go2rtc the Mi Home cloud token (from a logged-in Mi Home session).
3. Declare sources of the form
   `xiaomi://<did>@<relay-ip>?did=...&model=...&p2p_id=...&vendor=cs2`
   and let go2rtc handle the rest.

Use at your own risk, for cameras you own.

## 11. Final Implementation & Live Verification (2026-09-07)

The complete relay-media handoff is fully implemented, verified, and active in production:

1. **0xF9 Device Sockaddr Population**:
   - `buildRelayMediaAuth(...)` constructs the 84-byte auth packet with:
     - `[0:20]`: 20-byte `p2p_id` block.
     - `[20:36]`: capability block with connect-type byte 23 set to `0x02` (relay-media).
     - `[36:52]`: local sockaddr (`0002` + local port LE + local IP reversed + 8 zeros).
     - `[52:68]`: WAN sockaddr (`0002` + WAN port LE + WAN IP reversed + 8 zeros), derived from the relay STUN mapping.
     - `[68:84]`: DEVICE sockaddr (`0002` + relay-media `sessPort` LE + relay-media IP reversed + 8 zeros).
   - This associates the camera with the exact ephemeral relay-media session port discovered during the handshake.

2. **Choreographed Handshake Sequence**:
   - Client probes media candidates (`0x70` -> `0x71`).
   - Negotiates session via `0x72` -> receives `0x73` with `{sessNonce, sessPort}`.
   - Bursts `0x80` introduce frames (44 bytes total, 40-byte payload with `block[:17]`) to directory relays on `:32100`.
   - Relays reply with `0x81` ACKs.
   - Client immediately bursts `0x83` punches to the ephemeral `sessPort` on `:25000` / dynamic media port.
   - Relay-media server replies with `0x84` and `0x28` session frame.
   - Client echoes `0x28` with flag byte `0x02` and local sockaddr at `[68:84]`.
   - Client sends authenticated `0xF9` (carrying device sockaddr) to directory relays.
   - Relay-media server immediately begins streaming Channel 2 video (`0xD0`) and Channel 0 control frames directly to client.

3. **In-Flight Keepalive & Control**:
   - In `c.worker()`, `0x83` (media punches), `0x84` (punch acks), and `0x71` (probe acks) are cleanly handled without log pollution.
   - Periodic `0x28` session keepalives from the server are mirrored with `0x02` flag and local sockaddr.

4. **Production verification**:
   - Two hard-NAT cameras stream natively in 1080p HEVC (`width=1920, height=1080, fps=20`) over UDP relay-media without HLS transcoding latency.
   - Both report `route: cs2` and `live: true` on go2rtc's RTSP and WebRTC endpoints.
