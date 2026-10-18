"""bitchat-win: a partial, wire-compatible BitChat mesh node for Windows.

Central role (default) scans for real bitchat BLE peripherals, joins their
public mesh chat, and relays packets like any other hop, including
multi-hop relay of directed (private) packets, not just broadcasts. Public
messages, fragmentation, Noise-encrypted private DMs (`/dm <peer>
<message>`), public file/image sharing (`/img <path>`), private
(Noise-encrypted) file/image sharing (`/img-dm <peer> <path>`), bounded
voice notes (`/voice <seconds>`, `/voice-dm <peer> <seconds>`), Nostr
internet fallback for mutual favorites (`/favorite <peer>`) with optional
Tor routing (`BITCHAT_TOR_PROXY`), public geohash location channels
(`/geohash <geohash>`), and creator-managed E2EE private groups
(`/group create <name>`) are all implemented; see README for exactly what
is and isn't (live push-to-talk voice streaming).
"""
from __future__ import annotations

import asyncio
import logging
import mimetypes
import os
import sys
from datetime import datetime
from pathlib import Path

from bitchat import file_packet, groups, voice
from bitchat.ble_central import BLECentral
from bitchat.favorites import FavoritesStore
from bitchat.geohash_channel import GeohashChannelManager
from bitchat.groups import GroupManager
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine
from bitchat.nostr_event import NostrKind
from bitchat.nostr_identity import NostrIdentity, load_or_generate_device_seed
from bitchat.nostr_relay import NostrRelayPool

# `voice` (imported above) pulls in `sounddevice`, which wraps PortAudio,
# on Windows, PortAudio's WASAPI/DirectSound host APIs do an implicit
# CoInitialize() in STA mode (confirmed: MAIN_STA) as a side effect of
# merely importing it, before we ever touch Bluetooth. A thread's COM
# apartment can't be changed once set, so this silently poisons the same
# main thread bleak's WinRT scanner needs later: bleak's `assert_mta()` then
# waits up to 0.5s for a Windows message-loop timer callback that never
# arrives in a console app, and raises "Thread is configured for Windows GUI
# but callbacks are not working." Live-observed: scanner.start() hangs
# indefinitely instead of raising immediately, so this can silently sit for
# hours with zero peers ever appearing until something (e.g. Ctrl+C)
# finally unwinds it.
#
# bleak ships `uninitialize_sta()` for exactly this, but it only calls
# CoUninitialize() ONCE, decrementing a per-thread reference count, and
# PortAudio's own initialization was confirmed (live) to leave that count at
# 2, not 1, so a single call still leaves the apartment poisoned. Loop until
# CoGetApartmentType itself reports "not initialized".
if sys.platform == "win32":
    try:
        from bleak.backends.winrt.util import (
            _CO_E_NOTINITIALIZED,
            _get_apartment_type,
            uninitialize_sta,
        )

        for _ in range(10):
            try:
                _get_apartment_type()
            except OSError as _com_exc:
                if _com_exc.winerror == _CO_E_NOTINITIALIZED:
                    break
                raise
            uninitialize_sta()
    except Exception:  # noqa: BLE001 - best-effort; a failure here just means
        # assert_mta() surfaces its own error later, no worse than before this fix
        pass

RECEIVED_FILES_DIR = Path("received_files")
IDENTITY_FILE = Path("identity.json")
FAVORITES_FILE = Path("favorites.json")
GROUPS_FILE = Path("groups.json")
NOSTR_IDENTITY_FILE = Path("nostr_identity.json")
NOSTR_DEVICE_SEED_FILE = Path("nostr_device_seed.json")

logger = logging.getLogger("bitchat.cli")

# BITCHAT_DEBUG=1 turns on raw packet hex dumps (bitchat.ble_central,
# bitchat.mesh), useful for comparing our own outgoing packets against
# real ones received from other clients byte-for-byte when something isn't
# interoperating the way you'd expect.
_DEBUG = os.environ.get("BITCHAT_DEBUG") == "1"
logging.basicConfig(
    level=logging.DEBUG if _DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("bleak").setLevel(logging.INFO if _DEBUG else logging.WARNING)


def _print_over_prompt(text: str) -> None:
    print(f"\r{text}\n> ", end="", flush=True)


# (command, description), shared with tui.py, which reads this same list
# for both its inline "/"-suggester and /help, so the two entry points can't
# drift out of sync with each other.
COMMANDS = [
    ("/peers", "list peers seen this session"),
    ("/dm ", "<peer> <message>, send an encrypted private message"),
    ("/favorite ", "<peer>, enable Nostr fallback DMs with them"),
    ("/unfavorite ", "<peer>, disable Nostr fallback DMs with them"),
    ("/img ", "<path>, broadcast a file/image publicly"),
    ("/img-dm ", "<peer> <path>, send a file/image privately"),
    ("/voice ", "<seconds>, record + broadcast a voice note"),
    ("/voice-dm ", "<peer> <seconds>, record + send a voice note privately"),
    ("/group", "show current group typing status"),
    ("/group create ", "<name>, create a private E2EE group and switch to it"),
    ("/group ", "<name>, switch typing into an existing group"),
    ("/group invite ", "<peer>, invite someone to the active group (creator only)"),
    ("/group remove ", "<peer>, remove someone from the active group (creator only)"),
    ("/group leave", "leave the active group"),
    ("/group off", "stop typing into the active group without leaving"),
    ("/group list", "list all groups you're in"),
    ("/channel", "show current channel typing status"),
    ("/channel ", "<name>, join/switch typing into a fork-only #channel"),
    ("/channel leave", "leave the active channel"),
    ("/channel off", "stop typing into the active channel without leaving"),
    ("/channel list", "list channels you've joined"),
    ("/geohash", "show current geohash channel status"),
    ("/geohash ", "<geohash>, join/switch a public location channel"),
    ("/geohash off", "leave the current geohash channel"),
    ("/help", "show this command list"),
    ("/quit", "exit"),
]


# mimetypes.guess_type() reads its extension->type mapping from the Windows
# registry, which maps .jpg to the nonstandard "application/jpg" on at least
# this machine (every other common image extension came back correctly),
# a receiving bitchat client showed it verbatim as "application/jpg" instead
# of the standard "image/jpeg". Check this small override table of the
# common image types first so what we send matches what every other real
# client emits, regardless of one machine's registry quirks.
_MIME_OVERRIDES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".heic": "image/heic",
}


def _guess_mime_type(name: str) -> "str | None":
    override = _MIME_OVERRIDES.get(Path(name).suffix.lower())
    if override is not None:
        return override
    mime_type, _ = mimetypes.guess_type(name)
    return mime_type


def on_public_message(peer_id: str, sender: str, content: str) -> None:
    _print_over_prompt(f"<{sender}> {content}")


def on_peer_joined(peer_id: str, nickname: str) -> None:
    _print_over_prompt(f"* {nickname} joined the mesh ({peer_id})")


def on_peer_left(peer_id: str, nickname: str) -> None:
    _print_over_prompt(f"* {nickname} left the mesh")


def on_private_message(peer_id: str, sender: str, content: str) -> None:
    _print_over_prompt(f"[DM from {sender}] {content}")


def on_file_received(
    peer_id: str, sender: str, file_name: "str | None", mime_type: "str | None", content: bytes
) -> None:
    RECEIVED_FILES_DIR.mkdir(exist_ok=True)
    # Never trust a peer-supplied name as a path, take only the basename,
    # and fall back to something derived from the MIME type if there's none.
    safe_name = Path(file_name).name if file_name else None
    if not safe_name:
        ext = mimetypes.guess_extension(mime_type) if mime_type else None
        safe_name = f"{peer_id}-{len(content)}{ext or '.bin'}"
    dest = RECEIVED_FILES_DIR / safe_name
    if dest.exists():
        dest = RECEIVED_FILES_DIR / f"{dest.stem}-{peer_id[:6]}{dest.suffix}"
    dest.write_bytes(content)
    if voice.is_voice_note(file_name, mime_type):
        _print_over_prompt(f"* {sender} sent a voice note: {dest} ({len(content)} bytes)")
    else:
        _print_over_prompt(
            f"* {sender} sent a file: {dest} ({len(content)} bytes, {mime_type or 'unknown type'})"
        )


def on_private_file_received(
    peer_id: str, sender: str, file_name: "str | None", mime_type: "str | None", content: bytes
) -> None:
    RECEIVED_FILES_DIR.mkdir(exist_ok=True)
    safe_name = Path(file_name).name if file_name else None
    if not safe_name:
        ext = mimetypes.guess_extension(mime_type) if mime_type else None
        safe_name = f"{peer_id}-{len(content)}{ext or '.bin'}"
    dest = RECEIVED_FILES_DIR / f"dm-{safe_name}"
    if dest.exists():
        dest = RECEIVED_FILES_DIR / f"dm-{dest.stem}-{peer_id[:6]}{dest.suffix}"
    dest.write_bytes(content)
    if voice.is_voice_note(file_name, mime_type):
        _print_over_prompt(f"* {sender} sent you a private voice note: {dest} ({len(content)} bytes)")
    else:
        _print_over_prompt(
            f"* {sender} sent you a private file: {dest} ({len(content)} bytes, {mime_type or 'unknown type'})"
        )


def on_favorite_notice(peer_id: str, sender: str, is_favorite: bool, is_mutual: bool) -> None:
    action = "favorited" if is_favorite else "unfavorited"
    guidance = (
        " mutual! DMs can reach you over Nostr when out of mesh range."
        if is_mutual
        else " favorite them back (/favorite) to enable Nostr fallback."
        if is_favorite
        else ""
    )
    _print_over_prompt(f"* {sender} {action} you{guidance}")


def on_geohash_message(
    geohash: str, pubkey_hex: str, nickname: "str | None", content: str, teleported: bool
) -> None:
    label = nickname or f"anon{pubkey_hex[:4]}"
    tag = " [teleported]" if teleported else ""
    _print_over_prompt(f"[#{geohash}] <{label}>{tag} {content}")


def on_group_message(group_peer_id: str, group_name: str, sender_nickname: str, content: str) -> None:
    _print_over_prompt(f"[#{group_name}] <{sender_nickname}> {content}")


def on_group_notice(group_peer_id: str, group_name: str, notice: str) -> None:
    _print_over_prompt(f"* [#{group_name}] {notice}")


def on_channel_message(peer_id: str, sender: str, channel: str, content: str) -> None:
    # channel_prefix.py: there's no real wire-level delivery scoping for
    # "#channel"s: every public broadcast reaches every peer regardless,
    # same as a plain message. This just labels which channel it was tagged
    # for; it prints unconditionally, whether or not *we've* joined that
    # channel locally, exactly like a real phone (or any client that
    # doesn't understand this convention) would just see readable text.
    _print_over_prompt(f"[{channel}] <{sender}> {content}")


def _resolve_peer(mesh: MeshEngine, target: str) -> "str | None":
    """Matches by exact/prefix peer ID hex or by nickname (case-insensitive)
    so you don't have to copy-paste a 16-hex ID to send a DM."""
    target_lower = target.lower()
    for peer_id, nickname in mesh.peers.items():
        if peer_id == target_lower or peer_id.startswith(target_lower):
            return peer_id
    for peer_id, nickname in mesh.peers.items():
        if nickname.lower() == target_lower:
            return peer_id
    return None


def _resolve_group(mesh: MeshEngine, target: str) -> "groups.BitchatGroup | None":
    """Matches by name (case-insensitive) or group-ID hex prefix."""
    target_lower = target.lower()
    for group in mesh.list_groups():
        if group.name.lower() == target_lower:
            return group
    for group in mesh.list_groups():
        if group.group_id.hex().startswith(target_lower):
            return group
    return None


async def _record_voice_note(seconds: float) -> "bytes | None":
    """Records from the default mic and encodes to AAC/M4A, printing its own
    error and returning None on failure so callers can just check for that.
    Both steps run in an executor thread: recording blocks for the full
    duration and encoding shells out to ffmpeg, and the mesh needs to keep
    servicing BLE traffic on the event loop the whole time."""
    if seconds > voice.MAX_RECOMMENDED_SECONDS:
        print(
            f"warning: {seconds:.0f}s is likely too long to fit the mesh's "
            f"256-fragment delivery limit: proceeding anyway, but it may "
            f"fail to send (try {voice.MAX_RECOMMENDED_SECONDS}s or less)"
        )
    loop = asyncio.get_event_loop()
    print(f"recording {seconds:.1f}s from the default microphone...")
    try:
        pcm = await loop.run_in_executor(None, voice.record_pcm, seconds)
        m4a_bytes = await loop.run_in_executor(None, voice.encode_pcm_to_m4a, pcm)
    except voice.VoiceError as exc:
        print(f"couldn't record voice note: {exc}")
        return None
    return m4a_bytes


async def chat_loop(mesh: MeshEngine, ble: BLECentral, geohash_manager: GeohashChannelManager) -> None:
    loop = asyncio.get_event_loop()
    # Group typing mode, "#channel" typing mode, and geohash typing mode are
    # all mutually exclusive: entering one clears the others. Unlike
    # geohash (which has an explicit network join/subscribe step), both
    # groups and "#channel"s are just local state here, so there's nothing
    # to "join" over the network beyond picking which one typed lines go to
    # see channel_prefix.py for what a "#channel" actually is on the wire
    # (a plain text convention, not a real protocol feature).
    active_group_id: "bytes | None" = None
    joined_channels: "set[str]" = set()
    current_channel: "str | None" = None
    while True:
        try:
            line = await loop.run_in_executor(None, input, "> ")
        except EOFError:
            return  # stdin closed (e.g. piped input ran out, or Ctrl+D), shut down cleanly
        line = line.strip()
        if not line:
            continue
        if line == "/help":
            width = max(len(c) for c, _ in COMMANDS)
            for command, description in COMMANDS:
                print(f"  {command.ljust(width)}  {description}")
            continue
        if line in ("/quit", "/exit"):
            return
        if line == "/peers":
            if not mesh.peers:
                print("(no peers seen yet)")
            for peer_id, nickname in mesh.peers.items():
                record = mesh.favorites.get(peer_id) if mesh.favorites is not None else None
                tag = ""
                if record is not None and record.is_mutual:
                    tag = "  [mutual favorite]"
                elif record is not None and record.we_favorited:
                    tag = "  [favorited]"
                print(f"  {nickname}  ({peer_id}){tag}")
            continue
        if line.startswith("/favorite ") or line.startswith("/unfavorite "):
            is_favorite = line.startswith("/favorite ")
            target = line.partition(" ")[2].strip()
            peer_id = _resolve_peer(mesh, target)
            if peer_id is None:
                print(f"no known peer matching {target!r}, see /peers")
                continue
            if mesh.favorites is None:
                print("favorites are disabled")
                continue
            nickname = mesh.peers.get(peer_id, peer_id)
            mesh.favorites.set_we_favorited(peer_id, is_favorite, nickname)
            await mesh.send_favorite_notification(peer_id, is_favorite)
            verb = "favorited" if is_favorite else "unfavorited"
            print(f"{verb} {nickname}, notification sent (handshaking first if needed)")
            continue
        if line.startswith("/dm "):
            rest = line[len("/dm ") :]
            target, _, content = rest.partition(" ")
            if not content:
                print("usage: /dm <peer id or nickname> <message>")
                continue
            peer_id = _resolve_peer(mesh, target)
            if peer_id is None:
                print(f"no known peer matching {target!r}, see /peers")
                continue
            await mesh.send_private_message(peer_id, content)
            print(f"(sending private message to {mesh.peers.get(peer_id, peer_id)}, "
                  f"handshaking first if needed)")
            continue
        if line.startswith("/img "):
            path_str = line[len("/img ") :].strip().strip('"')
            path = Path(path_str)
            if not path.is_file():
                print(f"no such file: {path}")
                continue
            content = path.read_bytes()
            if len(content) > file_packet.MAX_PAYLOAD_BYTES:
                print(
                    f"{path} is {len(content)} bytes, over the "
                    f"{file_packet.MAX_PAYLOAD_BYTES}-byte (1 MiB) limit, not sent"
                )
                continue
            mime_type = _guess_mime_type(path.name)
            packets = mesh.build_file_transfer_packet(content, file_name=path.name, mime_type=mime_type)
            if packets is None:
                print(
                    f"couldn't send {path}: likely too large for the mesh's "
                    "256-fragment delivery limit (~115 KB after overhead), even "
                    "though it's under the 1 MiB TLV encoding limit"
                )
                continue
            await mesh.send_packets(packets)
            print(f"sent {path.name} ({len(content)} bytes, {mime_type or 'unknown type'})")
            continue
        if line.startswith("/img-dm "):
            rest = line[len("/img-dm ") :]
            target, _, path_str = rest.partition(" ")
            path_str = path_str.strip().strip('"')
            if not path_str:
                print("usage: /img-dm <peer id or nickname> <path>")
                continue
            peer_id = _resolve_peer(mesh, target)
            if peer_id is None:
                print(f"no known peer matching {target!r}, see /peers")
                continue
            path = Path(path_str)
            if not path.is_file():
                print(f"no such file: {path}")
                continue
            content = path.read_bytes()
            if len(content) > file_packet.MAX_PAYLOAD_BYTES:
                print(
                    f"{path} is {len(content)} bytes, over the "
                    f"{file_packet.MAX_PAYLOAD_BYTES}-byte (1 MiB) limit, not sent"
                )
                continue
            mime_type = _guess_mime_type(path.name)
            reason = await mesh.send_private_file(peer_id, content, file_name=path.name, mime_type=mime_type)
            if reason is not None:
                print(f"couldn't send {path} to {mesh.peers.get(peer_id, peer_id)}: {reason}")
                continue
            print(f"sent {path.name} privately to {mesh.peers.get(peer_id, peer_id)} "
                  f"({len(content)} bytes, {mime_type or 'unknown type'})")
            continue
        if line.startswith("/voice "):
            rest = line[len("/voice ") :].strip()
            try:
                seconds = float(rest)
            except ValueError:
                print("usage: /voice <seconds>")
                continue
            m4a_bytes = await _record_voice_note(seconds)
            if m4a_bytes is None:
                continue
            file_name = voice.make_voice_file_name(datetime.now())
            packets = mesh.build_file_transfer_packet(m4a_bytes, file_name=file_name, mime_type=voice.MIME_TYPE)
            if packets is None:
                print("voice note too large to send: see the mesh's 256-fragment delivery limit")
                continue
            await mesh.send_packets(packets)
            print(f"sent voice note {file_name} ({len(m4a_bytes)} bytes)")
            continue
        if line.startswith("/voice-dm "):
            rest = line[len("/voice-dm ") :]
            target, _, seconds_str = rest.partition(" ")
            seconds_str = seconds_str.strip()
            if not seconds_str:
                print("usage: /voice-dm <peer id or nickname> <seconds>")
                continue
            try:
                seconds = float(seconds_str)
            except ValueError:
                print("usage: /voice-dm <peer id or nickname> <seconds>")
                continue
            peer_id = _resolve_peer(mesh, target)
            if peer_id is None:
                print(f"no known peer matching {target!r}, see /peers")
                continue
            m4a_bytes = await _record_voice_note(seconds)
            if m4a_bytes is None:
                continue
            file_name = voice.make_voice_file_name(datetime.now())
            reason = await mesh.send_private_file(peer_id, m4a_bytes, file_name=file_name, mime_type=voice.MIME_TYPE)
            if reason is not None:
                print(f"couldn't send voice note to {mesh.peers.get(peer_id, peer_id)}: {reason}")
                continue
            print(f"sent voice note {file_name} privately to {mesh.peers.get(peer_id, peer_id)} "
                  f"({len(m4a_bytes)} bytes)")
            continue
        if line == "/group":
            if active_group_id is None:
                print("not currently typing into a group: /group <name> or /group create <name>")
            else:
                active_group = mesh.group_manager.group(active_group_id) if mesh.group_manager else None
                name = active_group.name if active_group else "group"
                member_count = len(active_group.members) if active_group else 0
                print(f"in #{name}, {member_count}/{groups.MAX_MEMBERS} members, typed lines go here")
            continue
        if line == "/group list":
            group_list = mesh.list_groups()
            if not group_list:
                print("(no groups yet, /group create <name>)")
            for group in group_list:
                role = " (creator)" if group.creator_fingerprint == mesh.identity.fingerprint_hex else ""
                print(f"  #{group.name}{role}, {len(group.members)}/{groups.MAX_MEMBERS} members")
            continue
        if line.startswith("/group create "):
            name = line[len("/group create ") :].strip()
            if not name:
                print("usage: /group create <name>")
                continue
            group = await mesh.create_group(name)
            if group is None:
                print("couldn't create group, groups are disabled" if mesh.group_manager is None else "couldn't create group")
                continue
            active_group_id = group.group_id
            current_channel = None
            await geohash_manager.leave()  # mutually exclusive typing destinations
            print(f"created #{group.name}: typed lines now go here. /group invite <peer> to add someone.")
            continue
        if line == "/group off":
            if active_group_id is None:
                print("not currently typing into a group")
            else:
                active_group_id = None
                print("stopped typing into that group (still a member: /group <name> to come back)")
            continue
        if line == "/group leave":
            if active_group_id is None:
                print("usage: /group <name> first, then /group leave")
                continue
            left_group = mesh.group_manager.group(active_group_id) if mesh.group_manager else None
            mesh.leave_group(active_group_id)
            active_group_id = None
            print(f"left #{left_group.name if left_group else 'group'}")
            continue
        if line.startswith("/group invite "):
            target = line[len("/group invite ") :].strip()
            if active_group_id is None:
                print("usage: /group <name> first, then /group invite <peer>")
                continue
            peer_id = _resolve_peer(mesh, target)
            if peer_id is None:
                print(f"no known peer matching {target!r}, see /peers")
                continue
            reason = await mesh.invite_to_group(active_group_id, peer_id)
            if reason is not None:
                print(f"couldn't invite: {reason}")
                continue
            print(f"invited {mesh.peers.get(peer_id, peer_id)}")
            continue
        if line.startswith("/group remove "):
            target = line[len("/group remove ") :].strip()
            if active_group_id is None:
                print("usage: /group <name> first, then /group remove <peer>")
                continue
            reason = await mesh.remove_from_group(active_group_id, target)
            if reason is not None:
                print(f"couldn't remove: {reason}")
                continue
            print(f"removed {target}")
            continue
        if line.startswith("/group "):
            target = line[len("/group ") :].strip()
            group = _resolve_group(mesh, target)
            if group is None:
                print(f"no known group matching {target!r}, see /group list")
                continue
            active_group_id = group.group_id
            current_channel = None
            await geohash_manager.leave()  # mutually exclusive typing destinations
            print(f"in #{group.name}: typed lines now go here (not the BLE mesh) until /group off.")
            continue
        if line == "/channel":
            if current_channel is None:
                print("not currently typing into a channel: /channel <name> to join one")
            else:
                print(f"in {current_channel}: typed lines now go here")
            continue
        if line == "/channel list":
            if not joined_channels:
                print("(no channels joined yet: /channel <name>)")
            for channel in sorted(joined_channels):
                marker = " (active)" if channel == current_channel else ""
                print(f"  {channel}{marker}")
            continue
        if line == "/channel off":
            if current_channel is None:
                print("not currently typing into a channel")
            else:
                current_channel = None
                print("stopped typing into that channel (still joined: /channel <name> to come back)")
            continue
        if line == "/channel leave":
            if current_channel is None:
                print("usage: /channel <name> first, then /channel leave")
                continue
            joined_channels.discard(current_channel)
            print(f"left {current_channel}")
            current_channel = None
            continue
        if line.startswith("/channel "):
            name = line[len("/channel ") :].strip()
            if not name:
                print("usage: /channel <name>")
                continue
            channel = name if name.startswith("#") else f"#{name}"
            joined_channels.add(channel)
            current_channel = channel
            active_group_id = None  # mutually exclusive typing destinations
            await geohash_manager.leave()
            print(f"in {channel}: typed lines now go here (not the general mesh) until /channel off. "
                  f"Note: real bitchat phones don't recognize this convention: they'll just see your "
                  f"messages as plain text with a visible '{channel}: ' prefix. See README.")
            continue
        if line == "/geohash":
            if geohash_manager.current_geohash is None:
                print("not currently in a geohash channel: /geohash <geohash> to join one")
            else:
                print(f"in #{geohash_manager.current_geohash}: "
                      f"{geohash_manager.participant_count()} participant(s) seen recently")
            continue
        if line in ("/geohash off", "/geohash-leave"):
            if geohash_manager.current_geohash is None:
                print("not currently in a geohash channel")
            else:
                left = geohash_manager.current_geohash
                await geohash_manager.leave()
                print(f"left #{left}")
            continue
        if line.startswith("/geohash "):
            raw = line[len("/geohash ") :].strip()
            try:
                joined = await geohash_manager.join(raw)
            except ValueError as exc:
                print(f"couldn't join: {exc}")
                continue
            active_group_id = None  # mutually exclusive typing destinations
            current_channel = None
            print(f"joined #{joined}: typed lines now go here (not the BLE mesh) "
                  f"until /geohash off. Messages from this client are always marked "
                  f"'teleported': see README (no GPS on this client to claim otherwise).")
            continue
        if geohash_manager.current_geohash is not None:
            await geohash_manager.send(line, nickname=mesh.nickname)
            continue
        if active_group_id is not None:
            reason = await mesh.send_group_message(active_group_id, line)
            if reason is not None:
                print(f"couldn't send to group: {reason}")
            continue
        if current_channel is not None:
            await mesh.send_packets(mesh.build_public_message_packet(line, channel=current_channel))
            continue
        await mesh.send_packets(mesh.build_public_message_packet(line))


async def _setup_peripheral(mesh: MeshEngine):
    """Best-effort peripheral (GATT server) startup, with a pre-flight check
    that catches the #1 real-world failure we hit building this: Windows
    silently blocking *all* BLE advertising via a policy value that (unlike
    our first guess) has no Control Panel or Group Policy toggle: see
    bitchat/diagnostics.py for the full story and why a plain capability-flag
    check can't detect this on its own; it takes an actual live probe."""
    try:
        from bitchat.ble_peripheral import BLEPeripheral
        from bitchat.diagnostics import check_peripheral_capability, offer_elevated_fix
    except ImportError as exc:
        logger.warning("peripheral role dependencies missing, continuing central-only: %s", exc)
        return None

    check = await check_peripheral_capability()
    if not check.ok and check.instructions:
        print(f"\nPeripheral role unavailable: {check.reason}")
        print(check.instructions)
        loop = asyncio.get_event_loop()
        if check.fixable_by_elevation:
            answer = await loop.run_in_executor(
                None, input, "\nApply this fix now via a Windows admin prompt (UAC)? [Y/n] "
            )
            if answer.strip().lower() not in ("n", "no"):
                if offer_elevated_fix():
                    await loop.run_in_executor(
                        None,
                        input,
                        "Approve the UAC prompt and wait for the PowerShell window to finish, "
                        "then press Enter here to retry... ",
                    )
                    check = await check_peripheral_capability()
                else:
                    print("Couldn't launch the elevated fix: see the manual steps above.")

    if not check.ok:
        print(
            f"\nPeripheral role still unavailable ({check.reason}): continuing in "
            "central-only mode. We can still join and relay in others' meshes, "
            "just not be dialed into directly. See README Known Issues.\n"
        )
        return None

    try:
        peripheral = BLEPeripheral(mesh)
        await peripheral.start()
        print("Peripheral role: advertising (other devices can connect to us).")
        return peripheral
    except Exception as exc:  # noqa: BLE001
        logger.warning("peripheral role passed pre-flight but still failed to start: %s", exc)
        print(f"Peripheral role failed to start despite passing pre-flight checks: {exc}")
        return None


async def main() -> None:
    print("bitchat-win: partial BitChat mesh client (central role, public chat only)")
    nickname = input("Nickname: ").strip()
    if not nickname:
        nickname = "windows-user"

    # Persistent, not regenerated every run: a real phone's "favorite" record
    # of us, and later our Nostr-fallback npub association, are both keyed
    # off this Noise pubkey fingerprint: a fresh random identity every
    # launch would silently orphan both.
    identity = Identity.load_or_generate(IDENTITY_FILE)
    print(f"Peer ID: {identity.peer_id_hex}")

    # A separate, also-persistent secp256k1 identity for Nostr fallback:
    # confirmed from the reference this is never derived from the mesh
    # Noise key, just its own freshly-generated-once keypair. Sharing it
    # (as an npub) only happens explicitly, via /favorite.
    nostr_identity = NostrIdentity.load_or_generate(NOSTR_IDENTITY_FILE)
    print(f"Nostr npub: {nostr_identity.npub}")

    mesh = MeshEngine(
        identity,
        nickname,
        on_public_message=on_public_message,
        on_peer_joined=on_peer_joined,
        on_peer_left=on_peer_left,
        on_private_message=on_private_message,
        on_file_received=on_file_received,
        on_private_file_received=on_private_file_received,
        favorites=FavoritesStore(FAVORITES_FILE),
        on_favorite_notice=on_favorite_notice,
        nostr_identity=nostr_identity,
        group_manager=GroupManager(GROUPS_FILE),
        on_group_message=on_group_message,
        on_group_notice=on_group_notice,
        on_channel_message=on_channel_message,
    )
    ble = BLECentral(mesh)

    async def on_nostr_event(event):
        # One relay pool, two unrelated kinds of traffic flowing through it:
        # gift-wrapped favorite DMs go to mesh's own handler; plain geohash
        # channel events (never gift-wrapped: see geohash.py) go to the
        # channel manager instead. geohash_manager isn't assigned until
        # after this closure is defined, below: fine, since it's only
        # looked up when an event actually arrives, by which point it exists.
        if event.kind == NostrKind.GIFT_WRAP:
            await mesh.handle_incoming_nostr_event(event)
        elif event.kind in (NostrKind.EPHEMERAL_EVENT, NostrKind.GEOHASH_PRESENCE):
            await geohash_manager.handle_incoming_event(event)

    # mesh needs a reference to the pool (to publish outgoing fallback
    # messages) and the pool needs a reference to mesh (to dispatch incoming
    # ones): construct mesh first, then wire the pool in after the fact.
    tor_proxy_url = os.environ.get("BITCHAT_TOR_PROXY")
    if tor_proxy_url:
        print(f"Routing Nostr relay connections through Tor ({tor_proxy_url}): "
              "assumes a real Tor process is already running there.")
    nostr_relay_pool = NostrRelayPool(nostr_identity.pubkey_hex, on_nostr_event, tor_proxy_url=tor_proxy_url)
    mesh.nostr_relay_pool = nostr_relay_pool

    # A separate per-geohash identity (never the persistent favorite-DM
    # npub) is derived from this device seed on each /geohash join: see
    # nostr_identity.py's derive_for_geohash.
    device_seed = load_or_generate_device_seed(NOSTR_DEVICE_SEED_FILE)
    geohash_manager = GeohashChannelManager(device_seed, nostr_relay_pool, on_message=on_geohash_message)

    await nostr_relay_pool.start()

    peripheral = None
    if os.environ.get("BITCHAT_PERIPHERAL") == "1":
        peripheral = await _setup_peripheral(mesh)
    else:
        print(
            "Peripheral role: skipped by default (opt in with BITCHAT_PERIPHERAL=1). "
            "Live testing found it reliably breaks central-role connections on this "
            "machine's radio when both run at once: see README Known Issues."
        )

    scan_task = asyncio.create_task(ble.run())
    try:
        await chat_loop(mesh, ble, geohash_manager)
    finally:
        scan_task.cancel()
        await ble.shutdown()
        await geohash_manager.leave()
        await nostr_relay_pool.stop()
        if peripheral is not None:
            peripheral.stop()
        try:
            await scan_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
