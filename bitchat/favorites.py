"""Favorite-peer persistence + the "[FAVORITED]"/"[UNFAVORITED]" mesh
control-message protocol that bootstraps Nostr fallback eligibility.

Ported from bitchat-android's FavoriteControlMessage.kt (exact wire string
format: `"[FAVORITED]:<npub>"` / `"[UNFAVORITED]:<npub-or-empty>"`, sent as
an ordinary private-message body over an existing Noise session, there's
no separate wire type for this, it rides the same NOISE_ENCRYPTED /
PRIVATE_MESSAGE path any text DM does) and FavoritesPersistenceService's
two-sided tracking model: "we favorited them" and "they favorited us" are
independent booleans, set from our own /favorite action and from
receiving their control message, respectively, and mutual is both being
true. Nostr fallback (see nostr_bridge.py) requires mutual favorite status
plus a known npub for the peer, matching MessageRouter.canSendViaNostr.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

FAVORITED_PREFIX = "[FAVORITED]"
UNFAVORITED_PREFIX = "[UNFAVORITED]"


def encode_favorite_control_message(is_favorite: bool, npub: Optional[str]) -> str:
    prefix = FAVORITED_PREFIX if is_favorite else UNFAVORITED_PREFIX
    return f"{prefix}:{npub or ''}"


def parse_favorite_control_message(content: str) -> Optional[Tuple[bool, Optional[str]]]:
    """Returns (is_favorite, npub_or_None) if `content` is a favorite control
    message, else None. Mirrors FavoriteControlMessage.parse exactly,
    including splitting on the *first* colon only (matches Kotlin's
    `substringAfter(":", "")`, not a strict "prefix:value" split)."""
    trimmed = content.strip()
    if trimmed.startswith(FAVORITED_PREFIX):
        is_favorite = True
    elif trimmed.startswith(UNFAVORITED_PREFIX):
        is_favorite = False
    else:
        return None
    _, _, rest = trimmed.partition(":")
    npub = rest.strip() or None
    return is_favorite, npub


@dataclass
class FavoriteRecord:
    peer_id_hex: str
    nickname: str = ""
    we_favorited: bool = False
    they_favorited: bool = False
    nostr_npub: Optional[str] = None

    @property
    def is_mutual(self) -> bool:
        return self.we_favorited and self.they_favorited


class FavoritesStore:
    """Persistent peer_id_hex -> FavoriteRecord map, loaded from and saved to
    a local JSON file. One instance per MeshEngine/identity, pass to
    MeshEngine(favorites=...) to enable the [FAVORITED] control-message
    handling in _handle_noise_encrypted; omit to disable the feature
    entirely (matches the optional on_file_received-style callback pattern
    used elsewhere in mesh.py)."""

    def __init__(self, path: Union[str, "os.PathLike[str]"]) -> None:
        self._path = Path(path)
        self._records: Dict[str, FavoriteRecord] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for peer_id_hex, fields in raw.items():
            self._records[peer_id_hex] = FavoriteRecord(peer_id_hex=peer_id_hex, **fields)

    def _save(self) -> None:
        raw = {
            peer_id_hex: {
                "nickname": r.nickname,
                "we_favorited": r.we_favorited,
                "they_favorited": r.they_favorited,
                "nostr_npub": r.nostr_npub,
            }
            for peer_id_hex, r in self._records.items()
        }
        self._path.write_text(json.dumps(raw, indent=2))

    def get(self, peer_id_hex: str) -> Optional[FavoriteRecord]:
        return self._records.get(peer_id_hex)

    def _get_or_create(self, peer_id_hex: str, nickname: str = "") -> FavoriteRecord:
        record = self._records.get(peer_id_hex)
        if record is None:
            record = FavoriteRecord(peer_id_hex=peer_id_hex, nickname=nickname)
            self._records[peer_id_hex] = record
        elif nickname:
            record.nickname = nickname
        return record

    def set_we_favorited(self, peer_id_hex: str, is_favorite: bool, nickname: str = "") -> FavoriteRecord:
        record = self._get_or_create(peer_id_hex, nickname)
        record.we_favorited = is_favorite
        self._save()
        return record

    def record_their_notification(
        self, peer_id_hex: str, is_favorite: bool, npub: Optional[str], nickname: str = ""
    ) -> FavoriteRecord:
        record = self._get_or_create(peer_id_hex, nickname)
        record.they_favorited = is_favorite
        if npub:
            record.nostr_npub = npub
        self._save()
        return record
