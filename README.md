# bitchat-win

A partial, wire-compatible Windows port of [bitchat](https://github.com/permissionlesstech/bitchat)'s
BLE mesh chat protocol. Implements the real binary wire format reverse-engineered
from bitchat's source, not a reimplementation from the whitepaper.

## Features

- **Identity**: X25519 + Ed25519 keypairs, PeerID derivation (`sha256(noise_pubkey)[:16]`)
  matching bitchat's own scheme.
- **Wire protocol**: `BitchatPacket` v1 header encode/decode, PKCS#7 padding, DEFLATE
  compression (send and receive), announce TLV, public message payload,
  `BitchatFilePacket` TLV for file/image transfer, fragmentation/reassembly for
  payloads too large for a single BLE write. Unit-tested against hand-built byte
  fixtures independent of the encoder (`tests/`).
- **Mesh relay**: TTL-decrementing relay with a fragment-aware dedup cache. Directed
  (private) packets are relayed too, not just broadcasts, matching
  bitchat-android's `PacketRelayManager` behavior. Every outgoing packet is
  Ed25519-signed, including Noise handshake/encrypted packets, matching real clients.
- **Private 1:1 DMs** (`bitchat/noise_session.py`, `noise_payload.py`): real
  `Noise_XX_25519_ChaChaPoly_SHA256` handshake plus bitchat's own on-wire framing
  (explicit 4-byte nonce prefix, TOFU peer-identity binding). `/dm <peer> <message>`.
  Verified against a real bitchat-android client.
- **Public and private file/image transfer** (`bitchat/file_packet.py`): `/img <path>`
  broadcasts, `/img-dm <peer> <path>` sends privately over an existing Noise session.
  Verified sending to a real bitchat-android client; receiving large multi-fragment
  transfers is unreliable on this machine, see Known issues.
- **Voice notes** (`bitchat/voice.py`): bounded (not live-streamed) recordings via
  `sounddevice`, encoded to AAC-in-MP4 via `ffmpeg`, sent through the file-transfer
  path. `/voice <seconds>`, `/voice-dm <peer> <seconds>`. Live push-to-talk streaming
  is not implemented.
- **Nostr fallback** (`bitchat/nostr_identity.py`, `nostr_crypto.py`, `nostr_event.py`,
  `nostr_bridge.py`, `nostr_relay.py`): for mutual favorites not currently on the mesh,
  falls back to a NIP-17-style gift-wrapped event over 4 public relays. Replicates
  bitchat's actual non-standard "NIP-44 v2" scheme (XChaCha20-Poly1305 as a single
  AEAD call, keyed from the compressed ECDH point) rather than the published NIP-44
  spec, since interop with real bitchat clients is the goal; this means bitchat's
  Nostr DMs are unreadable by standard Nostr clients. Requires `/favorite <peer>` on
  both sides and at least one prior BLE encounter to exchange favorite status.
- **Tor** (`bitchat/nostr_relay.py`): optionally routes relay connections through an
  external SOCKS5 proxy (`BITCHAT_TOR_PROXY=socks5://127.0.0.1:9050`). Assumes a Tor
  process is already running; does not manage one.
- **Geohash channels** (`bitchat/geohash.py`, `geohash_channel.py`): public,
  location-scoped chat over Nostr relays, matching both bitchat clients. `/geohash
  <geohash>` joins/switches channel. Each joined geohash gets its own throwaway
  Nostr identity derived from a persistent device seed, never the favorite-DM
  identity. Presence is only broadcast for geohash precision of 5 characters or
  coarser. Every message is marked `teleported` since this client has no GPS.
- **Private groups** (`bitchat/groups.py`): ported from bitchat-reference (iOS)'s
  `GroupProtocol.swift`; bitchat-android has no equivalent. A group is a random
  16-byte ID plus a 32-byte ChaCha20-Poly1305 key; the creator signs every
  roster/key change and distributes it over each member's Noise session. Any
  roster change rotates the key. Commands: `/group create <name>`, `/group <name>`,
  `/group invite <peer>`, `/group remove <peer>`, `/group leave`, `/group list`,
  `/group off`. The key is stored as plain local JSON (`groups.json`), unlike iOS's
  Keychain storage; a future improvement would use Windows DPAPI for this file.
- **`#channel` public mesh chat** (`bitchat/channel_prefix.py`): works around a real
  bug in bitchat-android's channel chat feature, where the outgoing packet builder
  accepts a `channel` parameter but never encodes it, so a channel-tagged message
  is indistinguishable on the wire from a public one. Fixed with a plain-text
  prefix convention (`"#general: hello"`) rather than a binary field, since iOS has
  no wire-level channel concept to be compatible with either. A message that
  happens to start with `"#word: "` is misread as a channel tag by receivers using
  this convention. Commands: `/channel <name>`, `/channel off`, `/channel leave`,
  `/channel list`, bare `/channel`.
- **Central role** (`bitchat/ble_central.py`, via `bleak`): scans for bitchat
  peripherals, connects, subscribes, joins the mesh. Verified against a real iOS
  and a real Android client. Failed connections back off before retrying the same
  address; writes run concurrently across links with a timeout so one degrading
  link doesn't stall delivery to others.
- **Peripheral role** (`bitchat/ble_peripheral.py`, WinRT GATT server): reaches the
  advertising state but is disabled by default (`BITCHAT_PERIPHERAL=1` to enable),
  see Known issues. Not required for interop since real bitchat clients run both
  roles, so this client's central role alone gets full bidirectional interop.

## Running it

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python cli.py          # plain text CLI
python tui.py          # full-screen terminal UI
python gui.py          # desktop GUI window
python gui.py --web    # same GUI in a browser
pytest                 # protocol unit tests, no radio required
```

`tui.py` and `gui.py` are additional entry points over the same `MeshEngine`/
`BLECentral`/Nostr stack as `cli.py`; all commands work identically across all
three. `BITCHAT_NICKNAME=yourname` skips the nickname prompt on either.

**Packaging a standalone `.exe`:**

```
pip install pyinstaller
flet pack gui.py -n bitchat-win -y --add-binary ".venv/Lib/site-packages/coincurve/libsecp256k1.dll:coincurve"
```

The `--add-binary` flag is required: `coincurve` loads `libsecp256k1.dll`
dynamically at runtime, so PyInstaller's static analysis misses it without
this flag, and the packed exe crashes on startup.

Voice notes need `ffmpeg` on PATH. Nostr fallback needs `coincurve`, `pynacl`,
`bech32`, and `websockets` (see `requirements.txt` for a `coincurve` version
pin needed on newer Python). Tor routing additionally needs `python-socks`
and a Tor process already running.

### Commands

`/peers` lists seen peers and favorite status. `/dm <peer> <message>` sends an
encrypted private message. `/favorite <peer>` / `/unfavorite <peer>` toggles
favorite status (required before Nostr fallback applies). `/img <path>` and
`/img-dm <peer> <path>` send files publicly or privately. `/voice <seconds>`
and `/voice-dm <peer> <seconds>` send voice notes. `/geohash <geohash>` joins a
location channel. `/group ...` manages private groups (see Features).
`/channel ...` manages fork-only text-prefix channels (see Features). `/quit`
exits and sends a leave packet. Received files and voice notes save to
`received_files/`.

Peripheral role: `BITCHAT_PERIPHERAL=1 python cli.py`. Verbose packet hex
dumps: `BITCHAT_DEBUG=1 python cli.py`.

## Known issues

**Peripheral role doesn't reliably work end-to-end** and is disabled by
default. Advertising can be blocked by a Windows policy value
(`HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth\AllowAdvertising`);
`bitchat/diagnostics.py`'s `offer_elevated_fix()` can set it (behind a UAC
prompt) and restart the `bthserv` service. Even with advertising reaching the
`STARTED` state, connecting to it from another device triggers Windows pairing
prompts real bitchat peers don't expect, and running peripheral and central
roles simultaneously measurably degraded central connectivity in testing.
When explicitly enabled, the client still runs a pre-flight check and falls
back to central-only (fully functional on its own) if peripheral setup fails.

**BLE connectivity can degrade over a long session** for reasons outside this
code; restarting the Windows Bluetooth adapter has resolved it in testing.

**Private DM limitations**: replay protection is a bounded recent-nonce set,
not a bit-packed sliding window; no rekeying on time/message-count thresholds.

**Multi-fragment receive reliability for large files/images is weak**, and
this is a Windows OS limitation rather than a decode bug: individually
captured fragments decode correctly, but GATT notifications (phone to PC) are
unacknowledged at the BLE link layer and Windows drops a meaningful fraction
of them under load. This is a documented, longstanding issue in the Windows
Bluetooth stack independent of the client implementation (confirmed via
multiple `bleak` GitHub issues reporting the same symptom), and bitchat itself
has no fragment-loss recovery mechanism to fall back on. Small messages and
DMs rarely hit this; large multi-fragment transfers are the ones exposed to it.

**Nostr fallback is verified at the crypto/network layer but not yet
end-to-end against a real phone.** The client connects to all 4 default relays
and the full gift-wrap encrypt/publish/receive/decrypt/unwrap chain round-trips
correctly in local testing (`tests/test_nostr_fallback.py`); what hasn't been
tried is going out of BLE range from a real phone and confirming delivery
purely over Nostr.

## Not implemented

Live push-to-talk voice streaming, location-notes/board content,
geo-relay-directory-based relay selection, session rekeying/expiry.

Private groups cannot be live-tested against this project's test phones since
the feature has no Android counterpart; it is verified only by matching the
iOS Swift source and an in-process integration test suite
(`tests/test_groups.py`, `tests/test_groups_mesh.py`).
