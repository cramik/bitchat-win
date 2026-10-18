"""bitchat-win TUI: a richer terminal interface over `mesh_session.py`'s
MeshSession, this file only renders (header, status bar, scrollable log,
a switcher menu) via `textual`; all mesh/protocol logic lives in
mesh_session.py, shared with gui.py.

Run with: `python tui.py`
"""
from __future__ import annotations

import os
from typing import List, Optional

from mesh_session import COMMANDS, Destination, MeshSession

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, RichLog, Static


class SwitcherItem(ListItem):
    def __init__(self, destination: Destination) -> None:
        super().__init__(Label(destination.label))
        self.destination = destination


class SwitcherScreen(ModalScreen[Optional[Destination]]):
    """F2 / Ctrl+K: pick which conversation typed lines go to."""

    DEFAULT_CSS = """
    SwitcherScreen {
        align: center middle;
    }
    #switcher-panel {
        width: 64;
        height: auto;
        max-height: 22;
        border: round $accent;
        background: $panel;
        padding: 1 2;
    }
    #switcher-panel Label {
        margin-bottom: 1;
    }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, destinations: List[Destination]) -> None:
        super().__init__()
        self._destinations = destinations

    def compose(self) -> ComposeResult:
        with Vertical(id="switcher-panel"):
            yield Label("Switch conversation  (Enter: select, Esc: cancel)")
            yield ListView(*(SwitcherItem(d) for d in self._destinations))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        assert isinstance(item, SwitcherItem)
        self.dismiss(item.destination)

    def action_cancel(self) -> None:
        self.dismiss(None)


class BitchatApp(App):
    """Full-screen terminal UI. All mesh/protocol logic lives in
    mesh_session.MeshSession, this class only renders it."""

    TITLE = "bitchat-win"
    # priority=True is load-bearing here: Textual's own Input widget binds
    # ctrl+k to "delete to end of line" and ctrl+c to "copy selection"
    # (readline-style, see Input.BINDINGS), since the Input has focus for
    # essentially the entire session, those widget-level bindings would
    # silently swallow ours first without priority=True, which makes an
    # App-level binding match *before* the focused widget gets a chance.
    BINDINGS = [
        Binding("f2", "open_switcher", "Switch", priority=True),
        Binding("ctrl+k", "open_switcher", "Switch", priority=True),
        Binding("f1", "show_help", "Help", priority=True),
        Binding("ctrl+c", "quit", "Quit", priority=True),
    ]
    CSS = """
    #status-bar {
        height: 1;
        background: $primary;
        color: $text;
        padding: 0 1;
        content-align: left middle;
    }
    #log {
        border: round $accent;
    }
    #input {
        margin-top: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.session: Optional[MeshSession] = None
        self._nickname_value = "windows-user"

    # layout

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="status-bar")
        yield RichLog(id="log", wrap=True, markup=False, highlight=False)
        yield Input(
            placeholder="Type a message or /command  (F1: help, F2: switch conversation)",
            id="input",
            suggester=SuggestFromList([c for c, _ in COMMANDS], case_sensitive=False),
        )
        yield Footer()

    def action_show_help(self) -> None:
        self.log_line("* Commands (Tab/→ to accept a suggestion as you type '/'):")
        width = max(len(c) for c, _ in COMMANDS)
        for command, description in COMMANDS:
            self.log_line(f"    {command.ljust(width)}  {description}")

    def on_mount(self) -> None:
        self.query_one("#input", Input).focus()
        self.session = MeshSession(self._nickname_value, on_log=self.log_line, on_status_change=self.update_status_bar)
        self.run_worker(self._run_setup(), exclusive=True, group="setup")

    async def _run_setup(self) -> None:
        await self.session.setup()
        self.log_line("* F1: help  |  F2 or Ctrl+K: switch conversation  |  type '/' for command suggestions")

    # logging / status bar

    def log_line(self, text: str) -> None:
        self.query_one("#log", RichLog).write(text)

    def update_status_bar(self) -> None:
        session = self.session
        nickname = session.mesh.nickname if session and session.mesh else "?"
        peer_count = len(session.mesh.peers) if session and session.mesh else 0
        destination_label = session.destination.label if session else "Mesh"
        self.query_one("#status-bar", Static).update(
            f"{nickname}  |  {destination_label}  |  {peer_count} peer(s) seen  |  F2/Ctrl+K: switch"
        )

    async def action_quit(self) -> None:
        if self.session is not None:
            await self.session.shutdown()
        self.exit()

    # switcher menu

    def action_open_switcher(self) -> None:
        if self.session is None or self.session.mesh is None:
            return
        self.push_screen(SwitcherScreen(self.session.all_destinations()), callback=self._on_switcher_result)

    def _on_switcher_result(self, destination: Optional[Destination]) -> None:
        if destination is None or self.session is None:
            return
        self.run_worker(self.session.apply_destination(destination), exclusive=False)

    # input handling

    def on_input_submitted(self, event: Input.Submitted) -> None:
        line = event.value.strip()
        event.input.value = ""
        if not line or self.session is None or self.session.mesh is None:
            return
        self.run_worker(
            self.session.handle_line(line, on_help=self.action_show_help, on_quit=self._quit_app),
            exclusive=False,
        )

    async def _quit_app(self) -> None:
        self.exit()


def main() -> None:
    app = BitchatApp()
    nickname = os.environ.get("BITCHAT_NICKNAME", "").strip()
    if not nickname:
        try:
            nickname = input("Nickname: ").strip()
        except EOFError:
            nickname = ""
    app._nickname_value = nickname or "windows-user"
    app.run()


if __name__ == "__main__":
    main()
