"""bitchat-win GUI: a real desktop app over `mesh_session.py`'s MeshSession,
this file only renders (nickname screen, sidebar of conversations, message
view, input box) via `flet`: all mesh/protocol logic lives in
mesh_session.py, shared with tui.py.

Run with: `python gui.py` (desktop window) or `python gui.py --web` (serves
on localhost so it can be opened in a browser: useful for headless
environments that can't show a native window).

Package as a standalone .exe: `flet pack gui.py` (see README).
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Optional

import flet as ft

from mesh_session import COMMANDS, Destination, MeshSession


class BitchatGUI:
    """Owns the Flet Page and renders whatever MeshSession's state is:
    same relationship tui.py's BitchatApp has to MeshSession, just with Flet
    controls instead of Textual widgets."""

    def __init__(self, page: ft.Page) -> None:
        self.page = page
        self.session: Optional[MeshSession] = None

        page.title = "bitchat-win"
        page.theme_mode = ft.ThemeMode.DARK
        page.padding = 0
        page.window.width = 1000
        page.window.height = 700

        self._show_nickname_screen()

    # nickname entry (Flet has no blocking input() equivalent, so this is
    # its own screen shown before the main UI is built) --------------------

    def _show_nickname_screen(self) -> None:
        env_nickname = os.environ.get("BITCHAT_NICKNAME", "").strip()
        if env_nickname:
            self._start_session(env_nickname)
            return

        nickname_field = ft.TextField(label="Nickname", autofocus=True, width=320, on_submit=self._on_nickname_submit)
        self._nickname_field = nickname_field

        self.page.controls.clear()
        self.page.add(
            ft.Column(
                [
                    ft.Text("bitchat-win", size=28, weight=ft.FontWeight.BOLD),
                    ft.Container(height=16),
                    nickname_field,
                    ft.Container(height=8),
                    ft.ElevatedButton("Continue", on_click=self._on_nickname_submit),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                expand=True,
            )
        )
        self.page.update()

    def _on_nickname_submit(self, e) -> None:
        nickname = (self._nickname_field.value or "").strip() or "windows-user"
        self._start_session(nickname)

    def _start_session(self, nickname: str) -> None:
        self.session = MeshSession(nickname, on_log=self._log_line, on_status_change=self._update_status)
        self._build_main_ui()
        self.page.run_task(self._run_setup)

    async def _run_setup(self) -> None:
        await self.session.setup()
        self._log_line("* Type '/help' for the full command list. Click a conversation in the sidebar to switch, or use /group, /channel, /geohash commands.")

    # main layout

    def _build_main_ui(self) -> None:
        self.status_text = ft.Text("", size=12, color=ft.Colors.ON_SURFACE_VARIANT)
        self.messages_view = ft.ListView(expand=True, spacing=4, auto_scroll=True, padding=10)
        self.sidebar_list = ft.Column(spacing=2, scroll=ft.ScrollMode.AUTO, expand=True)
        self.input_field = ft.TextField(
            hint_text="Type a message or /command (see /help)",
            expand=True,
            on_submit=self._on_input_submit,
            shift_enter=False,
        )

        sidebar = ft.Container(
            width=240,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            padding=10,
            content=ft.Column(
                [
                    ft.Row(
                        [ft.Text("Groups", weight=ft.FontWeight.BOLD, expand=True),
                         ft.IconButton(ft.Icons.ADD, tooltip="Create group", on_click=self._prefill_group_create)],
                    ),
                    ft.Row(
                        [ft.Text("Channels", weight=ft.FontWeight.BOLD, expand=True),
                         ft.IconButton(ft.Icons.ADD, tooltip="Join #channel", on_click=self._prefill_channel_join)],
                    ),
                    ft.Divider(height=1),
                    self.sidebar_list,
                ],
                expand=True,
            ),
        )

        main_column = ft.Column(
            [
                self.messages_view,
                ft.Row(
                    [
                        self.input_field,
                        ft.IconButton(ft.Icons.SEND, on_click=self._on_input_submit),
                    ]
                ),
            ],
            expand=True,
        )

        self.page.appbar = ft.AppBar(
            title=ft.Text("bitchat-win"),
            actions=[ft.Container(content=self.status_text, padding=ft.padding.Padding(right=16))],
        )
        self.page.controls.clear()
        self.page.add(ft.Row([sidebar, ft.VerticalDivider(width=1), main_column], expand=True))
        self.page.update()
        self._refresh_sidebar()

    # sidebar

    async def _prefill_group_create(self, e) -> None:
        self.input_field.value = "/group create "
        await self.input_field.focus()
        self.page.update()

    async def _prefill_channel_join(self, e) -> None:
        self.input_field.value = "/channel "
        await self.input_field.focus()
        self.page.update()

    def _refresh_sidebar(self) -> None:
        if self.session is None or self.session.mesh is None:
            return
        rows = []
        for destination in self.session.all_destinations():
            is_active = destination.kind == self.session.destination.kind and (
                (destination.kind == "mesh")
                or (destination.kind == "group" and destination.group_id == self.session.destination.group_id)
                or (destination.kind == "channel" and destination.channel == self.session.destination.channel)
                or (destination.kind == "geohash" and destination.geohash == self.session.destination.geohash)
            )
            rows.append(
                ft.Container(
                    content=ft.Text(destination.label, weight=ft.FontWeight.BOLD if is_active else ft.FontWeight.NORMAL),
                    padding=8,
                    border_radius=6,
                    bgcolor=ft.Colors.PRIMARY_CONTAINER if is_active else None,
                    on_click=lambda e, d=destination: self.page.run_task(self._switch_to, d),
                    ink=True,
                )
            )
        self.sidebar_list.controls = rows
        self.sidebar_list.update()

    async def _switch_to(self, destination: Destination) -> None:
        await self.session.apply_destination(destination)

    # logging / status

    def _log_line(self, text: str) -> None:
        self.messages_view.controls.append(ft.Text(text, selectable=True, font_family="Consolas"))
        self.messages_view.update()

    def _update_status(self) -> None:
        session = self.session
        nickname = session.mesh.nickname if session and session.mesh else "?"
        peer_count = len(session.mesh.peers) if session and session.mesh else 0
        destination_label = session.destination.label if session else "Mesh"
        self.status_text.value = f"{nickname}  |  {destination_label}  |  {peer_count} peer(s) seen"
        self.status_text.update()
        self._refresh_sidebar()

    # input

    def _on_input_submit(self, e) -> None:
        line = (self.input_field.value or "").strip()
        self.input_field.value = ""
        self.input_field.update()
        if not line or self.session is None or self.session.mesh is None:
            return
        self.page.run_task(self._handle_line, line)

    async def _handle_line(self, line: str) -> None:
        await self.session.handle_line(line, on_help=self._show_help, on_quit=self._on_quit)

    def _show_help(self) -> None:
        self._log_line("* Commands:")
        width = max(len(c) for c, _ in COMMANDS)
        for command, description in COMMANDS:
            self._log_line(f"    {command.ljust(width)}  {description}")

    async def _on_quit(self) -> None:
        self.page.window.close()


async def main(page: ft.Page) -> None:
    gui = BitchatGUI(page)

    async def on_disconnect(e):
        if gui.session is not None:
            await gui.session.shutdown()

    page.on_disconnect = on_disconnect


if __name__ == "__main__":
    view = ft.AppView.WEB_BROWSER if "--web" in sys.argv else ft.AppView.FLET_APP
    ft.run(main, view=view)
