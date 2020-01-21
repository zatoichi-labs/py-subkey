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
    return KeyringPair(BOB, key_type="ed25519")


def test_pairs(alice, bob):
    keyring = Keyring()  # Defaults to ed25519

    keyring.add_from_uri(ALICE)
    pair = keyring.pairs[-1]
    assert pair == alice
    assert len(keyring.pairs) == 1
    assert pair in keyring.pairs

    keyring.add_from_uri(BOB)
    pair = keyring.pairs[-1]
    assert pair == bob
    assert len(keyring.pairs) == 2
    assert pair in keyring.pairs
    assert alice in keyring.pairs
