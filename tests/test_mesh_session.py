"""Tests for mesh_session.MeshSession -- the shared command-dispatch and
destination-switching logic behind both tui.py and gui.py. No UI framework
involved at all: these construct a real MeshEngine (fake identity, no real
BLE/Nostr) and drive MeshSession directly, so they're fast and framework-
independent, and will keep covering gui.py's behavior too since it uses the
exact same class."""
import types

import pytest

from bitchat.identity import Identity
from bitchat.mesh import MeshEngine
from mesh_session import Destination, MeshSession


@pytest.fixture
def session():
    logged = []
    statuses = []
    s = MeshSession("tester", on_log=lambda text: logged.append(text), on_status_change=lambda: statuses.append(True))
    identity = Identity.generate()
    s.mesh = MeshEngine(identity, "tester", on_public_message=lambda *a: None)
    return s, logged


def test_initial_destination_is_mesh(session):
    s, _ = session
    assert s.destination.kind == "mesh"
    assert s.destination.label == "Mesh"


@pytest.mark.asyncio
async def test_typed_line_reaches_mesh_send_and_echoes_locally(session, monkeypatch):
    # Regression test: a rich UI's input control clears itself on submit, so
    # without an explicit local echo (on_log call) after a successful send,
    # the sender's own message never appears anywhere -- looking exactly
    # like sending silently failed even though it actually succeeded.
    s, logged = session
    sent = []

    async def fake_send_packets(packets):
        sent.append(packets)

    monkeypatch.setattr(s.mesh, "build_public_message_packet", lambda line, channel=None: [b"fake"])
    monkeypatch.setattr(s.mesh, "send_packets", fake_send_packets)

    await s.handle_line("hello mesh")

    assert sent == [[b"fake"]]
    assert any("hello mesh" in text for text in logged)


@pytest.mark.asyncio
async def test_group_create_switches_active_destination(session, monkeypatch):
    s, _ = session

    async def fake_create_group(name):
        return types.SimpleNamespace(group_id=b"\x01" * 16, name=name)

    monkeypatch.setattr(s.mesh, "create_group", fake_create_group)

    await s.handle_line("/group create TestGroup")

    assert s.destination.kind == "group"
    assert s.destination.group_id == b"\x01" * 16


@pytest.mark.asyncio
async def test_group_off_returns_to_mesh(session):
    s, _ = session
    s.destination = Destination("group", "[X]", group_id=b"\x02" * 16)

    await s.handle_line("/group off")

    assert s.destination.kind == "mesh"


@pytest.mark.asyncio
async def test_channel_join_and_leave(session):
    s, _ = session

    await s.handle_line("/channel general")
    assert s.destination.kind == "channel"
    assert s.destination.channel == "#general"
    assert "#general" in s.joined_channels

    await s.handle_line("/channel leave")
    assert s.destination.kind == "mesh"
    assert "#general" not in s.joined_channels


@pytest.mark.asyncio
async def test_channel_send_echoes_locally(session, monkeypatch):
    s, logged = session

    async def fake_send_packets(packets):
        pass

    monkeypatch.setattr(s.mesh, "build_public_message_packet", lambda line, channel=None: [b"fake"])
    monkeypatch.setattr(s.mesh, "send_packets", fake_send_packets)

    await s.handle_line("/channel general")
    logged.clear()
    await s.handle_line("hello channel")

    assert any("hello channel" in text and "#general" in text for text in logged)


@pytest.mark.asyncio
async def test_group_send_echoes_locally(session, monkeypatch):
    s, logged = session

    async def fake_create_group(name):
        return types.SimpleNamespace(group_id=b"\x01" * 16, name=name)

    async def fake_send_group_message(group_id, content):
        return None

    monkeypatch.setattr(s.mesh, "create_group", fake_create_group)
    monkeypatch.setattr(s.mesh, "send_group_message", fake_send_group_message)
    s.mesh.group_manager = types.SimpleNamespace(group=lambda gid: types.SimpleNamespace(name="TestGroup"))

    await s.handle_line("/group create TestGroup")
    logged.clear()
    await s.handle_line("hello group")

    assert any("hello group" in text and "TestGroup" in text for text in logged)


def test_all_destinations_lists_mesh_and_joined_channels(session):
    s, _ = session
    s.joined_channels.add("#dev")

    destinations = s.all_destinations()

    kinds_and_labels = [(d.kind, d.label) for d in destinations]
    assert ("mesh", "Mesh") in kinds_and_labels
    assert ("channel", "#dev") in kinds_and_labels


@pytest.mark.asyncio
async def test_quit_calls_shutdown_and_on_quit_callback(session, monkeypatch):
    s, _ = session

    async def fake_shutdown():
        pass

    monkeypatch.setattr(s, "shutdown", fake_shutdown)
    quit_called = []

    async def on_quit():
        quit_called.append(True)

    await s.handle_line("/quit", on_quit=on_quit)

    assert quit_called == [True]


@pytest.mark.asyncio
async def test_help_command_calls_on_help_callback(session):
    s, _ = session
    help_called = []

    await s.handle_line("/help", on_help=lambda: help_called.append(True))

    assert help_called == [True]
