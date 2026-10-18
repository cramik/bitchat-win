import hashlib
import os

from bitchat.nostr_identity import (
    NostrIdentity,
    generate_device_seed,
    hex_to_nsec,
    hex_to_npub,
    load_or_generate_device_seed,
    npub_to_hex,
    nsec_to_hex,
    save_device_seed,
    verify_schnorr,
)


def test_npub_bech32_round_trips():
    pubkey_hex = "7e" * 32
    npub = hex_to_npub(pubkey_hex)
    assert npub.startswith("npub1")
    assert npub_to_hex(npub) == pubkey_hex


def test_nsec_bech32_round_trips():
    privkey_hex = "3a" * 32
    nsec = hex_to_nsec(privkey_hex)
    assert nsec.startswith("nsec1")
    assert nsec_to_hex(nsec) == privkey_hex


def test_npub_rejects_wrong_hrp():
    nsec = hex_to_nsec("11" * 32)
    try:
        npub_to_hex(nsec)
        assert False, "expected ValueError for nsec passed to npub_to_hex"
    except ValueError:
        pass


def test_generate_produces_valid_schnorr_keypair():
    identity = NostrIdentity.generate()
    assert len(bytes.fromhex(identity.pubkey_hex)) == 32
    event_id = hashlib.sha256(b"some event bytes").digest()
    sig = identity.sign_event_id(event_id)
    assert len(sig) == 64
    assert verify_schnorr(identity.pubkey_hex, event_id, sig)


def test_signature_does_not_verify_against_a_different_event_id():
    identity = NostrIdentity.generate()
    event_id = hashlib.sha256(b"real event").digest()
    other_id = hashlib.sha256(b"tampered event").digest()
    sig = identity.sign_event_id(event_id)
    assert not verify_schnorr(identity.pubkey_hex, other_id, sig)


def test_npub_and_nsec_properties_match_bech32_helpers():
    identity = NostrIdentity.generate()
    assert identity.npub == hex_to_npub(identity.pubkey_hex)
    assert identity.nsec == hex_to_nsec(identity.private_key.secret.hex())
    assert identity.npub.startswith("npub1")
    assert identity.nsec.startswith("nsec1")


def test_load_or_generate_persists_the_same_keypair(tmp_path):
    path = tmp_path / "nostr_identity.json"
    first = NostrIdentity.load_or_generate(path)
    second = NostrIdentity.load_or_generate(path)
    assert second.pubkey_hex == first.pubkey_hex
    assert second.private_key.secret == first.private_key.secret


def test_device_seed_persists_across_calls(tmp_path):
    path = tmp_path / "device_seed.json"
    assert not path.exists()
    first = load_or_generate_device_seed(path)
    assert len(first) == 32
    second = load_or_generate_device_seed(path)
    assert second == first


def test_device_seed_save_and_load_round_trips():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "seed.json")
        seed = generate_device_seed()
        save_device_seed(seed, path)
        loaded = load_or_generate_device_seed(path)
        assert loaded == seed


def test_derive_for_geohash_is_deterministic_for_the_same_seed_and_geohash():
    seed = generate_device_seed()
    first = NostrIdentity.derive_for_geohash(seed, "9q8yyk")
    second = NostrIdentity.derive_for_geohash(seed, "9q8yyk")
    assert first.pubkey_hex == second.pubkey_hex
    assert first.private_key.secret == second.private_key.secret


def test_derive_for_geohash_differs_across_geohashes_and_seeds():
    seed = generate_device_seed()
    a = NostrIdentity.derive_for_geohash(seed, "9q8yyk")
    b = NostrIdentity.derive_for_geohash(seed, "u4pruy")
    assert a.pubkey_hex != b.pubkey_hex

    other_seed = generate_device_seed()
    c = NostrIdentity.derive_for_geohash(other_seed, "9q8yyk")
    assert c.pubkey_hex != a.pubkey_hex


def test_derive_for_geohash_produces_a_usable_signing_identity():
    seed = generate_device_seed()
    identity = NostrIdentity.derive_for_geohash(seed, "gbsuv")
    event_id = hashlib.sha256(b"some event").digest()
    sig = identity.sign_event_id(event_id)
    assert verify_schnorr(identity.pubkey_hex, event_id, sig)
