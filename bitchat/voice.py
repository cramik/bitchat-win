"""Voice notes: a bounded recording sent through the existing file-transfer
path, matching bitchat-android's "classic" fallback recording
(`VoiceRecorder.kt`), not the live push-to-talk `VOICE_FRAME`
burst-streaming layer (`LiveVoiceCapture.kt` / `docs/LIVE_VOICE_V1.md`).

The live layer needs a real-time, non-ADTS AAC-LC encoder emitting exact
1024-sample access units plus a jitter-buffered burst-session state machine
on receive (out-of-order buffering, gap-skip, per-burst quotas), real
complexity for a poor fit (a terminal has no "hold a key to talk" gesture).
It's also not the *only* delivery path: `VoiceRecorder.kt` itself falls back
to exactly this bounded-recording approach whenever there's no live route,
and that fallback is the one the reference source says produces MIME
`audio/mp4`. So this is a real, spec-compatible subset, not a shortcut that
happens to work: any client, ours or real, may not have live-streamed a
given voice note and still needs to render it from the file alone.

Wire identity as a voice note (vs. a generic audio attachment) is by
filename convention plus MIME, both confirmed from the reference:
`LiveVoiceManager.kt`: "`if (!fileName.startsWith("voice_")) return null`";
`VoiceRecorder.kt`: "The resulting file has MIME audio/mp4", filenames
`voice_<timestamp>.m4a`. `make_voice_file_name()`/`MIME_TYPE` below match
both exactly.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from datetime import datetime

import sounddevice as sd

# VoiceRecorder.kt / LiveVoiceCapture.kt: 16 kHz mono, 20 kbps AAC.
SAMPLE_RATE = 16_000
CHANNELS = 1
AAC_BITRATE = "20k"
MIME_TYPE = "audio/mp4"

# ~2.5 KB/s at 20 kbps, used only to warn the user before they sit through
# a recording that can't actually be sent (see fragment.MAX_FRAGMENTS).
APPROX_BYTES_PER_SECOND = 2_500

# Conservative: fragment.MAX_FRAGMENTS (256) * the smaller directed chunk
# size (454, since a private voice note has the tighter budget), minus
# generous headroom for the M4A container/TLV/Noise overhead this estimate
# doesn't otherwise account for. Purely advisory, the actual send call
# still enforces the real limit and reports the precise failure if this
# estimate is optimistic.
MAX_RECOMMENDED_SECONDS = 40


class VoiceError(Exception):
    """Recording or encoding failed, e.g. no mic, or ffmpeg missing."""


def make_voice_file_name(now: datetime) -> str:
    return "voice_" + now.strftime("%Y%m%d_%H%M%S") + ".m4a"


def is_voice_note(file_name: "str | None", mime_type: "str | None") -> bool:
    return (
        mime_type == MIME_TYPE
        and file_name is not None
        and file_name.startswith("voice_")
        and file_name.endswith(".m4a")
    )


def record_pcm(seconds: float) -> bytes:
    """Blocking mic capture, raw signed 16-bit little-endian mono PCM at
    SAMPLE_RATE, ready to feed straight into encode_pcm_to_m4a(). Run this in
    an executor thread, not directly on the asyncio loop: it blocks for the
    full recording duration and the mesh has to keep servicing BLE traffic
    while the user is talking."""
    if seconds <= 0:
        raise VoiceError("recording duration must be positive")
    frames_needed = int(seconds * SAMPLE_RATE)
    chunks = []
    try:
        with sd.RawInputStream(samplerate=SAMPLE_RATE, channels=CHANNELS, dtype="int16") as stream:
            remaining = frames_needed
            while remaining > 0:
                to_read = min(remaining, SAMPLE_RATE)  # read in ~1s chunks
                data, _overflowed = stream.read(to_read)
                chunks.append(bytes(data))
                remaining -= to_read
    except sd.PortAudioError as exc:
        raise VoiceError(f"couldn't record from the default microphone: {exc}") from exc
    return b"".join(chunks)


def encode_pcm_to_m4a(pcm_bytes: bytes) -> bytes:
    """Shells out to ffmpeg (Python has no native AAC encoder) to produce an
    AAC-in-MP4 (.m4a) file from raw PCM. Writes to a temp file rather than
    piping stdout, so ffmpeg can seek back and finalize a standard
    (non-fragmented) MP4, the most broadly compatible container for
    whatever real client/player ends up opening it."""
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise VoiceError("ffmpeg not found on PATH, required to encode voice notes to AAC/M4A")

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = os.path.join(tmp_dir, "voice.m4a")
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "s16le",
            "-ar",
            str(SAMPLE_RATE),
            "-ac",
            str(CHANNELS),
            "-i",
            "pipe:0",
            "-c:a",
            "aac",
            "-b:a",
            AAC_BITRATE,
            out_path,
        ]
        proc = subprocess.run(cmd, input=pcm_bytes, capture_output=True)
        if proc.returncode != 0:
            raise VoiceError(f"ffmpeg encode failed: {proc.stderr.decode(errors='replace').strip()}")
        with open(out_path, "rb") as f:
            return f.read()
