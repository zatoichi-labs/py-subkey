import pytest

from subkey import (
    Keyring,
    KeyringPair,
)

ALICE = "//Alice"
BOB   = "//Bob"


@pytest.fixture
def alice():
    return KeyringPair(ALICE, key_type="ed25519")


@pytest.fixture
def bob():
    return KeyringPair(BOB, "ed25519")


def test_pairs(alice, bob):
    keyring = Keyring()  # Defaults to ed25519

    pair = keyring.add_from_uri(ALICE)
    assert pair == alice
    assert len(keyring.pairs) == 1
    assert pair in keyring.pairs

    pair = keyring.add_from_uri(BOB)
    assert pair == bob
    assert pair in keyring.pairs
    assert len(keyring.pairs) == 2
