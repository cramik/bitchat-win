"""Noise_XX_25519_ChaChaPoly_SHA256 handshake + transport encryption for
private 1:1 messages.

Ported from bitchat-android-reference's NoiseSession.kt (driven there by
the real noise-java library). Here the handshake itself is driven by the
`noiseprotocol` PyPI package: Noise handshakes are fully spec-defined and
interoperable across compliant implementations, unlike bitchat's own
bespoke framing/compression/signing choices layered on top (those needed
byte-for-byte reverse engineering; this doesn't).

Two things bitchat does on top of a bare Noise library, both replicated
here by hand:

1. **Explicit per-message nonces on the wire**: `<4-byte BE counter>
   <ciphertext+16-byte Poly1305 tag>`, rather than trusting both sides to
   silently increment an internal counter in lockstep (BLE delivery order
   isn't guaranteed). `NoiseConnection.encrypt()/decrypt()` use an internal
   auto-incrementing nonce with no way to inspect or set it explicitly, so
   we bypass them: after the handshake, extract the raw 32-byte keys from
   the completed CipherStates and drive ChaCha20Poly1305 ourselves with the
   Noise-spec nonce encoding (4 zero bytes + 8-byte little-endian counter).
2. **Binding the handshake to a claimed peer identity**: the remote's
   static public key (learned mid-handshake) must derive the peer ID we
   thought we were handshaking with, or the session is rejected, defends
   against a spoofed announce claiming someone else's peer ID.

Deliberately simplified from the reference (see plan): the sliding-window
replay protection here is a bounded set of recently-seen counters rather
than the reference's bit-packed window, and there's no rekey/session
expiry. Functionally equivalent for a single short-lived DM session.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from noise.connection import Keypair, NoiseConnection
from noise.constants import Empty as _NoiseEmpty

from .identity import Identity, derive_peer_id_hex

_RAW = serialization.Encoding.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
NONCE_FIELD_SIZE = 4
REPLAY_WINDOW = 64


class NoiseSessionError(Exception):
    pass


class PeerIdentityMismatch(NoiseSessionError):
    pass


@dataclass
class _TransportKey:
    key: bytes
    counter: int = 0


class NoiseSession:
    def __init__(self, identity: Identity, peer_id_hex: str, is_initiator: bool) -> None:
        self.identity = identity
        self.peer_id_hex = peer_id_hex
        self.is_initiator = is_initiator
        self.established = False
        self.remote_static_public_key: Optional[bytes] = None

        self._messages_read = 0
        self._send_key: Optional[_TransportKey] = None
        self._recv_key: Optional[_TransportKey] = None
        self._seen_nonces: Set[int] = set()
        self._highest_seen_nonce = -1

        self._conn = NoiseConnection.from_name(PROTOCOL_NAME)
        if is_initiator:
            self._conn.set_as_initiator()
        else:
            self._conn.set_as_responder()
        self._conn.set_keypair_from_private_bytes(
            Keypair.STATIC,
            identity.noise_private.private_bytes(_RAW, _RAW_PRIV, _NO_ENC),
        )
        self._conn.start_handshake()

    def start_handshake(self) -> bytes:
        """Initiator only: produces XX message 1 (`e`, 32 bytes)."""
        if not self.is_initiator:
            raise NoiseSessionError("only the initiator calls start_handshake")
        return self._conn.write_message()

    def process_handshake_message(self, data: bytes) -> Optional[bytes]:
        """Feed in a received handshake message. Returns a response to send
        back, or None once the handshake is complete on our side.

        The XX pattern's message sequence is fixed, so whether a response
        is needed is determined by role + how many messages we've read, not
        by querying the library for an "expected action" (no such call is
        exposed by this library's public API anyway):
          - initiator: exactly one call here (processing message 2), always
            responds with message 3, which finishes the handshake.
          - responder: two calls, the first (message 1) always responds
            with message 2; the second (message 3) never responds and
            finishes the handshake purely by reading.
        """
        handshake_state = self._conn.noise_protocol.handshake_state
        self._conn.read_message(data)
        self._messages_read += 1
        self._bind_remote_key_if_learned(handshake_state)

        needs_response = self.is_initiator or self._messages_read == 1
        if not needs_response:
            if self._conn.handshake_finished:
                self._complete()
            return None

        response = self._conn.write_message()
        if self._conn.handshake_finished:
            self._complete()
        return response

    def _bind_remote_key_if_learned(self, handshake_state) -> None:
        if self.remote_static_public_key is not None:
            return
        rs = getattr(handshake_state, "rs", None)
        # The library uses its own `Empty` sentinel for "not set yet", not
        # None, checking `is None` alone silently never binds anything.
        if rs is None or isinstance(rs, _NoiseEmpty):
            return
        remote_key = rs.public_bytes
        derived = derive_peer_id_hex(remote_key)
        if derived != self.peer_id_hex:
            raise PeerIdentityMismatch(
                f"handshake claimed peer {self.peer_id_hex} but static key derives {derived}"
            )
        self.remote_static_public_key = remote_key

    def _complete(self) -> None:
        if self.remote_static_public_key is None:
            raise NoiseSessionError("handshake completed without binding a remote static key")
        proto = self._conn.noise_protocol
        self._send_key = _TransportKey(proto.cipher_state_encrypt.k)
        self._recv_key = _TransportKey(proto.cipher_state_decrypt.k)
        self.established = True

    @staticmethod
    def _nonce_bytes(counter: int) -> bytes:
        # Noise spec's ChaChaPoly nonce encoding: 4 zero bytes followed by
        # an 8-byte little-endian counter (96 bits total).
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "little")

    def encrypt(self, plaintext: bytes) -> bytes:
        if not self.established or self._send_key is None:
            raise NoiseSessionError("session not established")
        counter = self._send_key.counter
        self._send_key.counter += 1
        aead = ChaCha20Poly1305(self._send_key.key)
        ciphertext = aead.encrypt(self._nonce_bytes(counter), plaintext, None)
        return counter.to_bytes(NONCE_FIELD_SIZE, "big") + ciphertext

    def decrypt(self, payload: bytes) -> bytes:
        if not self.established or self._recv_key is None:
            raise NoiseSessionError("session not established")
        if len(payload) < NONCE_FIELD_SIZE:
            raise NoiseSessionError("payload too short for nonce field")
        counter = int.from_bytes(payload[:NONCE_FIELD_SIZE], "big")
        ciphertext = payload[NONCE_FIELD_SIZE:]

        if counter in self._seen_nonces or counter <= self._highest_seen_nonce - REPLAY_WINDOW:
            raise NoiseSessionError("replayed or too-old nonce")

        aead = ChaCha20Poly1305(self._recv_key.key)
        try:
            plaintext = aead.decrypt(self._nonce_bytes(counter), ciphertext, None)
        except InvalidTag as exc:
            raise NoiseSessionError("decryption failed") from exc

        self._seen_nonces.add(counter)
        if counter > self._highest_seen_nonce:
            self._highest_seen_nonce = counter
            self._seen_nonces = {n for n in self._seen_nonces if n > counter - REPLAY_WINDOW}
        return plaintext
