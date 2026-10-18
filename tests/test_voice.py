import asyncio
import math
import struct
from datetime import datetime

import pytest

from bitchat import voice
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine


def _synthetic_pcm(seconds: float, frequency: float = 440.0) -> bytes:
    """A plain sine tone, no numpy needed -- just enough real audio content
    for ffmpeg to have something to actually encode (silence would work for
    the encode-succeeds tests too, but a real waveform makes it obvious if
    the output were empty/garbage rather than merely not-erroring)."""
    n_samples = int(seconds * voice.SAMPLE_RATE)
    samples = (
        int(32767 * math.sin(2 * math.pi * frequency * (i / voice.SAMPLE_RATE)))
        for i in range(n_samples)
    )
    return b"".join(struct.pack("<h", s) for s in samples)


def test_make_voice_file_name_matches_reference_convention():
    # bitchat-android's VoiceRecorder.kt: "voice_" + yyyyMMdd_HHmmss + ".m4a"
    name = voice.make_voice_file_name(datetime(2026, 3, 5, 14, 30, 7))
    assert name == "voice_20260305_143007.m4a"


def test_is_voice_note_requires_prefix_suffix_and_mime():
    assert voice.is_voice_note("voice_20260305_143007.m4a", "audio/mp4")
    assert not voice.is_voice_note("song.m4a", "audio/mp4")  # missing voice_ prefix
    assert not voice.is_voice_note("voice_20260305_143007.mp3", "audio/mp4")  # wrong extension
    assert not voice.is_voice_note("voice_20260305_143007.m4a", "audio/mpeg")  # wrong mime
    assert not voice.is_voice_note(None, "audio/mp4")


def test_encode_pcm_to_m4a_produces_a_valid_aac_container():
    pcm = _synthetic_pcm(0.5)
    encoded = voice.encode_pcm_to_m4a(pcm)
    assert len(encoded) > 100
    # MP4/M4A containers carry an "ftyp" box near the start identifying the
    # container format -- a cheap, dependency-free sanity check that this
    # is a real container and not empty/garbage ffmpeg output.
    assert b"ftyp" in encoded[:32]


def test_encode_pcm_to_m4a_raises_clearly_when_ffmpeg_missing(monkeypatch):
    monkeypatch.setattr(voice.shutil, "which", lambda _name: None)
    with pytest.raises(voice.VoiceError, match="ffmpeg"):
        voice.encode_pcm_to_m4a(_synthetic_pcm(0.1))


def test_record_pcm_rejects_nonpositive_duration():
    with pytest.raises(voice.VoiceError):
        voice.record_pcm(0)
    with pytest.raises(voice.VoiceError):
        voice.record_pcm(-1.0)


def test_public_voice_note_round_trips_through_the_mesh_and_is_recognized():
    # Confirms the actual AAC/M4A bytes (not just arbitrary content, like
    # test_file_transfer.py's random bytes) survive the file-transfer TLV +
    # fragmentation path intact, and that a receiver can tell it's a voice
    # note (not just any file) purely from file_name + mime_type.
    identity_a = Identity.generate()
    identity_b = Identity.generate()
    received = []
    alice = MeshEngine(identity_a, "alice", on_public_message=lambda *a: None)
    bob = MeshEngine(
        identity_b,
        "bob",
        on_public_message=lambda *a: None,
        on_file_received=lambda peer_id, sender, name, mime, content: received.append(
            (peer_id, sender, name, mime, content)
        ),
    )

    m4a_bytes = voice.encode_pcm_to_m4a(_synthetic_pcm(1.0))
    file_name = voice.make_voice_file_name(datetime(2026, 3, 5, 9, 0, 0))
    packets = alice.build_file_transfer_packet(m4a_bytes, file_name=file_name, mime_type=voice.MIME_TYPE)
    assert packets is not None
    for raw in packets:
        asyncio.run(bob.handle_incoming(raw, link_id="a"))

    assert len(received) == 1
    _, _, name, mime, content = received[0]
    assert content == m4a_bytes
    assert voice.is_voice_note(name, mime)
