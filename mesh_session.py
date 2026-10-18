"""Shared mesh session logic for both rich UIs (`tui.py`, `gui.py`) over the
exact same MeshEngine/BLECentral/Nostr stack `cli.py` uses.

This exists so the full command surface (every `/dm`, `/group`, `/channel`,
`/geohash`, ... handler) and the destination-switching state machine live in
exactly one place. It was split out of tui.py after gui.py needed the
identical logic, before this, a fix (like the missing local-echo bug) would
have had to land twice and could silently drift out of sync between the two
UIs. Neither UI does any mesh-protocol work of its own; they only render
`MeshSession`'s state and call its methods.

Importing `cli` re-runs its module-level side effects (the STA/MTA COM
apartment fix for bleak's WinRT scanner, and logging setup) and gives us its
already-written, non-UI helpers (`_resolve_peer`, `_resolve_group`,
`_guess_mime_type`, `COMMANDS`) for free, see cli.py's own docstring for
why those exist. `cli.py` itself is untouched and still works standalone.
"""
from __future__ import annotations

import asyncio
import mimetypes
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Awaitable, Callable, List, Optional

import cli  # noqa: F401, import side effect: STA/MTA fix + logging setup; also reused below
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

COMMANDS = cli.COMMANDS  # single source of truth, see cli.py's definition


@dataclass
class Destination:
    """Where typed lines currently go, one mutually-exclusive value instead
    of cli.py's chat_loop's three separate local variables
    (active_group_id / current_channel / geohash). Both UIs' switcher/status
    display just read/set this."""

    kind: str  # "mesh" | "group" | "channel" | "geohash"
    label: str
    group_id: Optional[bytes] = None
    channel: Optional[str] = None
    geohash: Optional[str] = None


MESH_DESTINATION = Destination("mesh", "Mesh")


class MeshSession:
    """Owns the MeshEngine/BLECentral/Nostr stack and the full command
    dispatch. `on_log` receives every line that should appear in the UI's
    message view; `on_status_change` is called whenever the peer count,
    nickname, or active destination might have changed, so the UI can
    refresh its own status display without polling."""

    def __init__(
        self,
        nickname: str,
        on_log: Callable[[str], None],
        on_status_change: Callable[[], None] = lambda: None,
    ) -> None:
        self.nickname = nickname
        self.on_log = on_log
        self.on_status_change = on_status_change

        self.destination: Destination = MESH_DESTINATION
        self.joined_channels: set = set()
        self.mesh: Optional[MeshEngine] = None
        self.ble: Optional[BLECentral] = None
        self.geohash_manager: Optional[GeohashChannelManager] = None
        self.nostr_relay_pool: Optional[NostrRelayPool] = None
        self._scan_task: Optional[asyncio.Task] = None
        self._shutting_down = False

    #, setup / shutdown (mirrors cli.py's main(), minus interactive prompts),

    async def setup(self) -> None:
        identity = Identity.load_or_generate(cli.IDENTITY_FILE)
        self.on_log(f"* Peer ID: {identity.peer_id_hex}")

        nostr_identity = NostrIdentity.load_or_generate(cli.NOSTR_IDENTITY_FILE)
        self.on_log(f"* Nostr npub: {nostr_identity.npub}")

        self.mesh = MeshEngine(
            identity,
            self.nickname,
            on_public_message=self._on_public_message,
            on_peer_joined=self._on_peer_joined,
            on_peer_left=self._on_peer_left,
            on_private_message=self._on_private_message,
            on_file_received=self._on_file_received,
            on_private_file_received=self._on_private_file_received,
            favorites=FavoritesStore(cli.FAVORITES_FILE),
            on_favorite_notice=self._on_favorite_notice,
            nostr_identity=nostr_identity,
            group_manager=GroupManager(cli.GROUPS_FILE),
            on_group_message=self._on_group_message,
            on_group_notice=self._on_group_notice,
            on_channel_message=self._on_channel_message,
        )
        self.ble = BLECentral(self.mesh)

        async def on_nostr_event(event):
            if event.kind == NostrKind.GIFT_WRAP:
                await self.mesh.handle_incoming_nostr_event(event)
            elif event.kind in (NostrKind.EPHEMERAL_EVENT, NostrKind.GEOHASH_PRESENCE):
                await self.geohash_manager.handle_incoming_event(event)

        tor_proxy_url = os.environ.get("BITCHAT_TOR_PROXY")
        if tor_proxy_url:
            self.on_log(f"* Routing Nostr relay connections through Tor ({tor_proxy_url})")
        self.nostr_relay_pool = NostrRelayPool(nostr_identity.pubkey_hex, on_nostr_event, tor_proxy_url=tor_proxy_url)
        self.mesh.nostr_relay_pool = self.nostr_relay_pool

        device_seed = load_or_generate_device_seed(cli.NOSTR_DEVICE_SEED_FILE)
        self.geohash_manager = GeohashChannelManager(
            device_seed, self.nostr_relay_pool, on_message=self._on_geohash_message
        )

        await self.nostr_relay_pool.start()

        if os.environ.get("BITCHAT_PERIPHERAL") == "1":
            # Unlike cli.py's _setup_peripheral, this deliberately skips the
            # interactive UAC-elevation prompt flow, mixing a second
            # blocking input() prompt with a rich UI's own input widget
            # doesn't fit either UI. Run cli.py directly first if you need
            # that guided fix.
            try:
                from bitchat.diagnostics import check_peripheral_capability

                check = await check_peripheral_capability()
                if check.ok:
                    from bitchat.ble_peripheral import BLEPeripheral

                    peripheral = BLEPeripheral(self.mesh)
                    await peripheral.start()
                    self.on_log("* Peripheral role: advertising (other devices can connect to us).")
                else:
                    self.on_log(f"* Peripheral role unavailable ({check.reason}), continuing central-only.")
            except Exception as exc:  # noqa: BLE001
                self.on_log(f"* Peripheral role failed to start: {exc}")
        else:
            self.on_log("* Peripheral role: skipped by default (opt in with BITCHAT_PERIPHERAL=1).")

        self._scan_task = asyncio.create_task(self.ble.run())
        self.on_status_change()

    async def shutdown(self) -> None:
        if self._shutting_down:
            return
        self._shutting_down = True
        if self._scan_task is not None:
            self._scan_task.cancel()
        if self.ble is not None:
            await self.ble.shutdown()
        if self.geohash_manager is not None:
            await self.geohash_manager.leave()
        if self.nostr_relay_pool is not None:
            await self.nostr_relay_pool.stop()
        if self._scan_task is not None:
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass

    # mesh callbacks (mirror cli.py's on_* functions)

    def _on_public_message(self, peer_id: str, sender: str, content: str) -> None:
        self.on_log(f"<{sender}> {content}")

    def _on_peer_joined(self, peer_id: str, nickname: str) -> None:
        self.on_log(f"* {nickname} joined the mesh ({peer_id})")
        self.on_status_change()

    def _on_peer_left(self, peer_id: str, nickname: str) -> None:
        self.on_log(f"* {nickname} left the mesh")
        self.on_status_change()

    def _on_private_message(self, peer_id: str, sender: str, content: str) -> None:
        self.on_log(f"[DM from {sender}] {content}")

    def _on_file_received(self, peer_id, sender, file_name, mime_type, content) -> None:
        cli.RECEIVED_FILES_DIR.mkdir(exist_ok=True)
        safe_name = Path(file_name).name if file_name else None
        if not safe_name:
            ext = mimetypes.guess_extension(mime_type) if mime_type else None
            safe_name = f"{peer_id}-{len(content)}{ext or '.bin'}"
        dest = cli.RECEIVED_FILES_DIR / safe_name
        if dest.exists():
            dest = cli.RECEIVED_FILES_DIR / f"{dest.stem}-{peer_id[:6]}{dest.suffix}"
        dest.write_bytes(content)
        if voice.is_voice_note(file_name, mime_type):
            self.on_log(f"* {sender} sent a voice note: {dest} ({len(content)} bytes)")
        else:
            self.on_log(f"* {sender} sent a file: {dest} ({len(content)} bytes, {mime_type or 'unknown type'})")

    def _on_private_file_received(self, peer_id, sender, file_name, mime_type, content) -> None:
        cli.RECEIVED_FILES_DIR.mkdir(exist_ok=True)
        safe_name = Path(file_name).name if file_name else None
        if not safe_name:
            ext = mimetypes.guess_extension(mime_type) if mime_type else None
            safe_name = f"{peer_id}-{len(content)}{ext or '.bin'}"
        dest = cli.RECEIVED_FILES_DIR / f"dm-{safe_name}"
        if dest.exists():
            dest = cli.RECEIVED_FILES_DIR / f"dm-{dest.stem}-{peer_id[:6]}{dest.suffix}"
        dest.write_bytes(content)
        if voice.is_voice_note(file_name, mime_type):
            self.on_log(f"* {sender} sent you a private voice note: {dest} ({len(content)} bytes)")
        else:
            self.on_log(
                f"* {sender} sent you a private file: {dest} ({len(content)} bytes, {mime_type or 'unknown type'})"
            )

    def _on_favorite_notice(self, peer_id: str, sender: str, is_favorite: bool, is_mutual: bool) -> None:
        action = "favorited" if is_favorite else "unfavorited"
        guidance = (
            ", mutual! DMs can reach you over Nostr when out of mesh range."
            if is_mutual
            else ", favorite them back (/favorite) to enable Nostr fallback."
            if is_favorite
            else ""
        )
        self.on_log(f"* {sender} {action} you{guidance}")

    def _on_geohash_message(self, geohash: str, pubkey_hex: str, nickname, content: str, teleported: bool) -> None:
        label = nickname or f"anon{pubkey_hex[:4]}"
        tag = " [teleported]" if teleported else ""
        self.on_log(f"[#{geohash}] <{label}>{tag} {content}")

    def _on_group_message(self, group_peer_id: str, group_name: str, sender_nickname: str, content: str) -> None:
        self.on_log(f"[#{group_name}] <{sender_nickname}> {content}")

    def _on_group_notice(self, group_peer_id: str, group_name: str, notice: str) -> None:
        self.on_log(f"* [#{group_name}] {notice}")

    def _on_channel_message(self, peer_id: str, sender: str, channel: str, content: str) -> None:
        self.on_log(f"[{channel}] <{sender}> {content}")

    #, destination switching (single source of truth for all three modes),

    async def switch_to_mesh(self) -> None:
        if self.geohash_manager is not None:
            await self.geohash_manager.leave()
        self.destination = MESH_DESTINATION
        self.on_status_change()

    async def switch_to_group(self, group_id: bytes, label: str) -> None:
        if self.geohash_manager is not None:
            await self.geohash_manager.leave()
        self.destination = Destination("group", label, group_id=group_id)
        self.on_status_change()

    async def switch_to_channel(self, channel: str) -> None:
        if self.geohash_manager is not None:
            await self.geohash_manager.leave()
        self.joined_channels.add(channel)
        self.destination = Destination("channel", channel, channel=channel)
        self.on_status_change()

    async def switch_to_geohash(self, geohash: str) -> str:
        joined = await self.geohash_manager.join(geohash)
        self.destination = Destination("geohash", f"#{joined}", geohash=joined)
        self.on_status_change()
        return joined

    def all_destinations(self) -> List[Destination]:
        destinations = [MESH_DESTINATION]
        for group in self.mesh.list_groups():
            destinations.append(Destination("group", f"[{group.name}]", group_id=group.group_id))
        for channel in sorted(self.joined_channels):
            destinations.append(Destination("channel", channel, channel=channel))
        if self.geohash_manager is not None and self.geohash_manager.current_geohash is not None:
            destinations.append(
                Destination(
                    "geohash", f"#{self.geohash_manager.current_geohash}", geohash=self.geohash_manager.current_geohash
                )
            )
        return destinations

    async def apply_destination(self, destination: Destination) -> None:
        """Applies a Destination picked from all_destinations() (e.g. via a
        switcher UI), the tap-to-switch equivalent of typing /group <name>
        etc."""
        if destination.kind == "mesh":
            await self.switch_to_mesh()
        elif destination.kind == "group":
            await self.switch_to_group(destination.group_id, destination.label)
        elif destination.kind == "channel":
            await self.switch_to_channel(destination.channel)
        elif destination.kind == "geohash":
            await self.switch_to_geohash(destination.geohash)

    # voice notes

    async def record_voice_note(self, seconds: float) -> Optional[bytes]:
        if seconds > voice.MAX_RECOMMENDED_SECONDS:
            self.on_log(
                f"* warning: {seconds:.0f}s is likely too long to fit the mesh's 256-fragment "
                f"delivery limit, proceeding anyway (try {voice.MAX_RECOMMENDED_SECONDS}s or less)"
            )
        loop = asyncio.get_event_loop()
        self.on_log(f"* recording {seconds:.1f}s from the default microphone...")
        try:
            pcm = await loop.run_in_executor(None, voice.record_pcm, seconds)
            m4a_bytes = await loop.run_in_executor(None, voice.encode_pcm_to_m4a, pcm)
        except voice.VoiceError as exc:
            self.on_log(f"* couldn't record voice note: {exc}")
            return None
        return m4a_bytes

    # command dispatch

    async def handle_line(
        self,
        line: str,
        on_help: Callable[[], None] = lambda: None,
        on_quit: Callable[[], Awaitable[None]] = None,
    ) -> None:
        """Full command surface, ported from cli.py's chat_loop, same
        commands, same behavior, just calling `self.on_log` instead of
        print() and reading/setting `self.destination` instead of three
        separate local variables. `on_help`/`on_quit` let each UI show its
        own command list / do its own app-exit teardown; the mesh-level
        shutdown always happens here regardless."""
        mesh = self.mesh
        say = self.on_log

        if line == "/help":
            on_help()
            return
        if line in ("/quit", "/exit"):
            await self.shutdown()
            if on_quit is not None:
                await on_quit()
            return
        if line == "/peers":
            if not mesh.peers:
                say("(no peers seen yet)")
            for peer_id, nickname in mesh.peers.items():
                record = mesh.favorites.get(peer_id) if mesh.favorites is not None else None
                tag = ""
                if record is not None and record.is_mutual:
                    tag = "  [mutual favorite]"
                elif record is not None and record.we_favorited:
                    tag = "  [favorited]"
                say(f"  {nickname}  ({peer_id}){tag}")
            return
        if line.startswith("/favorite ") or line.startswith("/unfavorite "):
            is_favorite = line.startswith("/favorite ")
            target = line.partition(" ")[2].strip()
            peer_id = cli._resolve_peer(mesh, target)
            if peer_id is None:
                say(f"no known peer matching {target!r}, see /peers")
                return
            if mesh.favorites is None:
                say("favorites are disabled")
                return
            nickname = mesh.peers.get(peer_id, peer_id)
            mesh.favorites.set_we_favorited(peer_id, is_favorite, nickname)
            await mesh.send_favorite_notification(peer_id, is_favorite)
            verb = "favorited" if is_favorite else "unfavorited"
            say(f"{verb} {nickname}, notification sent (handshaking first if needed)")
            return
        if line.startswith("/dm "):
            rest = line[len("/dm ") :]
            target, _, content = rest.partition(" ")
            if not content:
                say("usage: /dm <peer id or nickname> <message>")
                return
            peer_id = cli._resolve_peer(mesh, target)
            if peer_id is None:
                say(f"no known peer matching {target!r}, see /peers")
                return
            await mesh.send_private_message(peer_id, content)
            say(f"(sending private message to {mesh.peers.get(peer_id, peer_id)}, handshaking first if needed)")
            return
        if line.startswith("/img "):
            path_str = line[len("/img ") :].strip().strip('"')
            path = Path(path_str)
            if not path.is_file():
                say(f"no such file: {path}")
                return
            content = path.read_bytes()
            if len(content) > file_packet.MAX_PAYLOAD_BYTES:
                say(
                    f"{path} is {len(content)} bytes, over the "
                    f"{file_packet.MAX_PAYLOAD_BYTES}-byte (1 MiB) limit, not sent"
                )
                return
            mime_type = cli._guess_mime_type(path.name)
            packets = mesh.build_file_transfer_packet(content, file_name=path.name, mime_type=mime_type)
            if packets is None:
                say(f"couldn't send {path}, likely too large for the mesh's 256-fragment delivery limit")
                return
            await mesh.send_packets(packets)
            say(f"sent {path.name} ({len(content)} bytes, {mime_type or 'unknown type'})")
            return
        if line.startswith("/img-dm "):
            rest = line[len("/img-dm ") :]
            target, _, path_str = rest.partition(" ")
            path_str = path_str.strip().strip('"')
            if not path_str:
                say("usage: /img-dm <peer id or nickname> <path>")
                return
            peer_id = cli._resolve_peer(mesh, target)
            if peer_id is None:
                say(f"no known peer matching {target!r}, see /peers")
                return
            path = Path(path_str)
            if not path.is_file():
                say(f"no such file: {path}")
                return
            content = path.read_bytes()
            if len(content) > file_packet.MAX_PAYLOAD_BYTES:
                say(
                    f"{path} is {len(content)} bytes, over the "
                    f"{file_packet.MAX_PAYLOAD_BYTES}-byte (1 MiB) limit, not sent"
                )
                return
            mime_type = cli._guess_mime_type(path.name)
            reason = await mesh.send_private_file(peer_id, content, file_name=path.name, mime_type=mime_type)
            if reason is not None:
                say(f"couldn't send {path} to {mesh.peers.get(peer_id, peer_id)}: {reason}")
                return
            say(f"sent {path.name} privately to {mesh.peers.get(peer_id, peer_id)} ({len(content)} bytes)")
            return
        if line.startswith("/voice "):
            rest = line[len("/voice ") :].strip()
            try:
                seconds = float(rest)
            except ValueError:
                say("usage: /voice <seconds>")
                return
            m4a_bytes = await self.record_voice_note(seconds)
            if m4a_bytes is None:
                return
            file_name = voice.make_voice_file_name(datetime.now())
            packets = mesh.build_file_transfer_packet(m4a_bytes, file_name=file_name, mime_type=voice.MIME_TYPE)
            if packets is None:
                say("voice note too large to send, see the mesh's 256-fragment delivery limit")
                return
            await mesh.send_packets(packets)
            say(f"sent voice note {file_name} ({len(m4a_bytes)} bytes)")
            return
        if line.startswith("/voice-dm "):
            rest = line[len("/voice-dm ") :]
            target, _, seconds_str = rest.partition(" ")
            seconds_str = seconds_str.strip()
            if not seconds_str:
                say("usage: /voice-dm <peer id or nickname> <seconds>")
                return
            try:
                seconds = float(seconds_str)
            except ValueError:
                say("usage: /voice-dm <peer id or nickname> <seconds>")
                return
            peer_id = cli._resolve_peer(mesh, target)
            if peer_id is None:
                say(f"no known peer matching {target!r}, see /peers")
                return
            m4a_bytes = await self.record_voice_note(seconds)
            if m4a_bytes is None:
                return
            file_name = voice.make_voice_file_name(datetime.now())
            reason = await mesh.send_private_file(peer_id, m4a_bytes, file_name=file_name, mime_type=voice.MIME_TYPE)
            if reason is not None:
                say(f"couldn't send voice note to {mesh.peers.get(peer_id, peer_id)}: {reason}")
                return
            say(f"sent voice note {file_name} privately to {mesh.peers.get(peer_id, peer_id)} ({len(m4a_bytes)} bytes)")
            return
        if line == "/group":
            if self.destination.kind != "group":
                say("not currently in a group, /group <name>, /group create <name>, or the switcher")
            else:
                group = mesh.group_manager.group(self.destination.group_id) if mesh.group_manager else None
                name = group.name if group else "group"
                member_count = len(group.members) if group else 0
                say(f"in #{name}, {member_count}/{groups.MAX_MEMBERS} members, typed lines go here")
            return
        if line == "/group list":
            group_list = mesh.list_groups()
            if not group_list:
                say("(no groups yet, /group create <name>)")
            for group in group_list:
                role = " (creator)" if group.creator_fingerprint == mesh.identity.fingerprint_hex else ""
                say(f"  #{group.name}{role}, {len(group.members)}/{groups.MAX_MEMBERS} members")
            return
        if line.startswith("/group create "):
            name = line[len("/group create ") :].strip()
            if not name:
                say("usage: /group create <name>")
                return
            group = await mesh.create_group(name)
            if group is None:
                say("couldn't create group, groups are disabled" if mesh.group_manager is None else "couldn't create group")
                return
            await self.switch_to_group(group.group_id, f"[{group.name}]")
            say(f"created #{group.name}, typed lines now go here. /group invite <peer> to add someone.")
            return
        if line == "/group off":
            if self.destination.kind != "group":
                say("not currently in a group")
            else:
                await self.switch_to_mesh()
                say("stopped typing into that group (still a member)")
            return
        if line == "/group leave":
            if self.destination.kind != "group":
                say("usage: /group <name> first, then /group leave")
                return
            group_id = self.destination.group_id
            left_group = mesh.group_manager.group(group_id) if mesh.group_manager else None
            mesh.leave_group(group_id)
            await self.switch_to_mesh()
            say(f"left #{left_group.name if left_group else 'group'}")
            return
        if line.startswith("/group invite "):
            target = line[len("/group invite ") :].strip()
            if self.destination.kind != "group":
                say("usage: /group <name> first, then /group invite <peer>")
                return
            peer_id = cli._resolve_peer(mesh, target)
            if peer_id is None:
                say(f"no known peer matching {target!r}, see /peers")
                return
            reason = await mesh.invite_to_group(self.destination.group_id, peer_id)
            if reason is not None:
                say(f"couldn't invite: {reason}")
                return
            say(f"invited {mesh.peers.get(peer_id, peer_id)}")
            return
        if line.startswith("/group remove "):
            target = line[len("/group remove ") :].strip()
            if self.destination.kind != "group":
                say("usage: /group <name> first, then /group remove <peer>")
                return
            reason = await mesh.remove_from_group(self.destination.group_id, target)
            if reason is not None:
                say(f"couldn't remove: {reason}")
                return
            say(f"removed {target}")
            return
        if line.startswith("/group "):
            target = line[len("/group ") :].strip()
            group = cli._resolve_group(mesh, target)
            if group is None:
                say(f"no known group matching {target!r}, see /group list")
                return
            await self.switch_to_group(group.group_id, f"[{group.name}]")
            say(f"in #{group.name}, typed lines now go here until /group off.")
            return
        if line == "/channel":
            if self.destination.kind != "channel":
                say("not currently in a channel, /channel <name> or the switcher")
            else:
                say(f"in {self.destination.channel}, typed lines now go here")
            return
        if line == "/channel list":
            if not self.joined_channels:
                say("(no channels joined yet, /channel <name>)")
            for channel in sorted(self.joined_channels):
                marker = " (active)" if self.destination.kind == "channel" and channel == self.destination.channel else ""
                say(f"  {channel}{marker}")
            return
        if line == "/channel off":
            if self.destination.kind != "channel":
                say("not currently in a channel")
            else:
                await self.switch_to_mesh()
                say("stopped typing into that channel (still joined)")
            return
        if line == "/channel leave":
            if self.destination.kind != "channel":
                say("usage: /channel <name> first, then /channel leave")
                return
            self.joined_channels.discard(self.destination.channel)
            left = self.destination.channel
            await self.switch_to_mesh()
            say(f"left {left}")
            return
        if line.startswith("/channel "):
            name = line[len("/channel ") :].strip()
            if not name:
                say("usage: /channel <name>")
                return
            channel = name if name.startswith("#") else f"#{name}"
            await self.switch_to_channel(channel)
            say(
                f"in {channel}, typed lines now go here until /channel off. Note: real bitchat "
                f"phones don't recognize this convention, they'll just see your messages as plain "
                f"text with a visible '{channel}: ' prefix. See README."
            )
            return
        if line == "/geohash":
            if self.geohash_manager.current_geohash is None:
                say("not currently in a geohash channel, /geohash <geohash> to join one")
            else:
                say(
                    f"in #{self.geohash_manager.current_geohash}, "
                    f"{self.geohash_manager.participant_count()} participant(s) seen recently"
                )
            return
        if line in ("/geohash off", "/geohash-leave"):
            if self.geohash_manager.current_geohash is None:
                say("not currently in a geohash channel")
            else:
                left = self.geohash_manager.current_geohash
                await self.switch_to_mesh()
                say(f"left #{left}")
            return
        if line.startswith("/geohash "):
            raw = line[len("/geohash ") :].strip()
            try:
                joined = await self.switch_to_geohash(raw)
            except ValueError as exc:
                say(f"couldn't join: {exc}")
                return
            say(
                f"joined #{joined}, typed lines now go here until /geohash off. Messages from this "
                f"client are always marked 'teleported', see README (no GPS on this client)."
            )
            return

        # Plain typed line: route by current destination, exactly like
        # cli.py's chat_loop priority chain (geohash > group > channel > mesh).
        #
        # Every branch below echoes what was sent into the log. cli.py never
        # needs to (your typed line just stays visible at the terminal's own
        # "> " prompt), but a rich UI's input control typically clears
        # itself immediately on submit, so without an explicit echo your own
        # messages would never appear anywhere, looking exactly like
        # sending silently failed, even though delivery succeeded.
        if self.destination.kind == "geohash":
            await self.geohash_manager.send(line, nickname=mesh.nickname)
            say(f"[#{self.destination.geohash}] <{mesh.nickname}> {line}")
            return
        if self.destination.kind == "group":
            reason = await mesh.send_group_message(self.destination.group_id, line)
            if reason is not None:
                say(f"couldn't send to group: {reason}")
            else:
                group = mesh.group_manager.group(self.destination.group_id) if mesh.group_manager else None
                say(f"[#{group.name if group else 'group'}] <{mesh.nickname}> {line}")
            return
        if self.destination.kind == "channel":
            await mesh.send_packets(mesh.build_public_message_packet(line, channel=self.destination.channel))
            say(f"[{self.destination.channel}] <{mesh.nickname}> {line}")
            return
        await mesh.send_packets(mesh.build_public_message_packet(line))
        say(f"<{mesh.nickname}> {line}")
