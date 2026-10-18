"""Headless smoke tests for tui.py using Textual's run_test() (a virtual
terminal, no real TTY needed).

These only cover Textual-specific rendering/wiring concerns (mounting, the
status bar, key bindings, the Input-to-MeshSession wire-up) -- the actual
command dispatch and destination-switching logic lives in mesh_session.py
and is covered framework-independently in test_mesh_session.py, since tui.py
doesn't implement any of that itself anymore."""
import pytest

import tui
from bitchat.identity import Identity
from bitchat.mesh import MeshEngine
from mesh_session import MeshSession
from textual.widgets import Input, Static


@pytest.fixture
def app(monkeypatch):
    application = tui.BitchatApp()
    application._nickname_value = "tester"

    async def fake_setup(self):
        identity = Identity.generate()
        self.mesh = MeshEngine(identity, "tester", on_public_message=lambda *a: None)
        self.on_status_change()

    monkeypatch.setattr(MeshSession, "setup", fake_setup)
    return application


@pytest.mark.asyncio
async def test_app_mounts_and_shows_mesh_destination(app):
    async with app.run_test() as pilot:
        await pilot.pause()
        status = app.query_one("#status-bar", Static).content
        assert "Mesh" in str(status)
        assert app.session.destination.kind == "mesh"


@pytest.mark.asyncio
async def test_typed_line_reaches_handle_line(app, monkeypatch):
    received = []

    async def fake_handle_line(line, on_help=None, on_quit=None):
        received.append(line)

    async with app.run_test() as pilot:
        await pilot.pause()
        monkeypatch.setattr(app.session, "handle_line", fake_handle_line)

        input_widget = app.query_one("#input", Input)
        input_widget.value = "hello mesh"
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()  # handle_line runs as a worker -- give it a beat to complete

        assert received == ["hello mesh"]
        assert input_widget.value == ""  # cleared on submit


@pytest.mark.asyncio
async def test_switcher_lists_mesh_and_joined_channels(app):
    async with app.run_test() as pilot:
        await pilot.pause()
        app.session.joined_channels.add("#dev")

        destinations = app.session.all_destinations()

        kinds_and_labels = [(d.kind, d.label) for d in destinations]
        assert ("mesh", "Mesh") in kinds_and_labels
        assert ("channel", "#dev") in kinds_and_labels


@pytest.mark.asyncio
async def test_ctrl_k_opens_switcher_even_though_input_has_focus(app):
    """Regression test: Textual's own Input widget binds ctrl+k to "delete to
    end of line" (readline-style, see Input.BINDINGS) and the Input has
    focus for virtually the whole session -- without priority=True on the
    app-level binding, that widget-level binding silently wins and the
    switcher never opens. Confirmed broken without priority=True before this
    test was written; this asserts the fix, not just the intent."""
    async with app.run_test() as pilot:
        await pilot.pause()
        input_widget = app.query_one("#input", Input)
        assert input_widget.has_focus
        input_widget.value = "some text that ctrl+k would otherwise truncate"

        await pilot.press("ctrl+k")
        await pilot.pause()

        assert isinstance(app.screen, tui.SwitcherScreen)
        # And not swallowed as "delete to end of line" by the Input widget:
        assert input_widget.value == "some text that ctrl+k would otherwise truncate"


@pytest.mark.asyncio
async def test_help_command_lists_every_command(app):
    async with app.run_test() as pilot:
        await pilot.pause()

        await app.session.handle_line("/help", on_help=app.action_show_help)

        # RichLog doesn't expose its written lines directly for assertion,
        # so this just confirms the handler runs the real, shared COMMANDS
        # list without raising -- the list itself is asserted for coverage.
        assert ("/help", "show this command list") in tui.COMMANDS
        assert ("/quit", "exit") in tui.COMMANDS
        assert len(tui.COMMANDS) > 10
