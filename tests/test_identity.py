import hashlib

from bitchat.identity import Identity, derive_peer_id_hex, peer_id_to_routing_bytes


def test_peer_id_matches_sha256_fingerprint_of_pubkey():
    pubkey = b"\x07" * 32
    expected = hashlib.sha256(pubkey).hexdigest()[:16]
    assert derive_peer_id_hex(pubkey) == expected


def test_routing_bytes_are_8_bytes_and_reversible():
    peer_id_hex = derive_peer_id_hex(b"\x09" * 32)
    routing = peer_id_to_routing_bytes(peer_id_hex)
    assert len(routing) == 8
    assert routing.hex() == peer_id_hex


def test_generate_produces_consistent_identity():
    identity = Identity.generate()
    assert len(identity.noise_public_bytes) == 32
    assert len(identity.signing_public_bytes) == 32
    assert identity.peer_id_hex == derive_peer_id_hex(identity.noise_public_bytes)
    assert identity.routing_id == bytes.fromhex(identity.peer_id_hex)


def test_load_or_generate_persists_across_calls(tmp_path):
    path = tmp_path / "identity.json"
    assert not path.exists()

    first = Identity.load_or_generate(path)
    assert path.exists()

    second = Identity.load_or_generate(path)
    assert second.peer_id_hex == first.peer_id_hex
    assert second.noise_public_bytes == first.noise_public_bytes
    assert second.signing_public_bytes == first.signing_public_bytes


def test_save_and_load_round_trips_the_same_private_keys(tmp_path):
    path = tmp_path / "identity.json"
    original = Identity.generate()
    original.save(path)

    loaded = Identity.load_or_generate(path)
    assert loaded.peer_id_hex == original.peer_id_hex
    # Same private key material, not just the same derived public identity --
    # sign with one, verify with the other's public key.
    sig = loaded.signing_private.sign(b"proof")
    original.signing_public.verify(sig, b"proof")  # raises if the keys differ
