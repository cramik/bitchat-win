"""Fork-only convention for scoping a public mesh broadcast to a named
`#channel`, WITHOUT touching the wire format real bitchat clients expect.

Verified against bitchat-reference (the real iOS Swift source): a public
MessageType.MESSAGE payload is `Data(content.utf8)`, plain UTF-8 text,
nothing else (BLEService.swift's sendMessage). BitchatMessage.swift's own
richer TLV encoder (with a channel field) is only ever called from that
codebase's test fixtures, never a live send path, so encoding a channel tag
as a binary field makes a real unmodified bitchat phone show garbled bytes
instead of the message.

This encodes the channel as a plain, human-readable text prefix instead:
"#general: hello" is exactly what goes out as the packet payload. A real
phone (or any client not aware of this convention) just sees ordinary, fully
readable text with a visible prefix, never garbled, never broken, just not
auto-filtered into a channel bucket on their end. Only clients that know this
convention (this fork, and bitchat-android-fork which uses the identical
format, see its ChannelTextPrefix.kt) parse the prefix back out to restore
per-channel bucketing locally.

Known, accepted tradeoff: an ordinary message that happens to start with
"#someword: " (single word, no spaces, immediately followed by ": ") will be
mis-parsed as a channel tag by a receiver using this convention, even if the
sender never joined or intended any channel. This is a real ambiguity
inherent to a plain-text convention with no dedicated wire field, accepted
deliberately in exchange for zero binary-compatibility risk with real
bitchat clients. See README for the full writeup.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

_PREFIX_PATTERN = re.compile(r"^(#\S+): ([\s\S]*)$")


def encode(content: str, channel: Optional[str]) -> str:
    """Builds the actual wire text for an outgoing message. Returns `content`
    unchanged when `channel` is None."""
    if channel is None:
        return content
    return f"{channel}: {content}"


def decode(text: str) -> Tuple[Optional[str], str]:
    """Splits decoded plain-text payload back into (channel, content) if it
    matches the "#channel: " prefix convention, else (None, the original
    text unchanged)."""
    match = _PREFIX_PATTERN.match(text)
    if match is None:
        return None, text
    return match.group(1), match.group(2)
