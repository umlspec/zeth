from math import ceil
from os import urandom
from typing import Tuple
from hashlib import sha256
from py_ecc import bn128 as ec

from zeth.utils import encode_single, encode_abi
import zeth.constants as constants

FQ = ec.FQ
G1 = Tuple[ec.FQ, ec.FQ]


class SchnorrVerificationKey:
    """
    A Joinsplit secret and public keypair.
    """
    def __init__(self, x_g1: G1, y_g1: G1):
        self.ppk = x_g1
        self.spk = y_g1

class SchnorrSigningKey:
    """
    A Joinsplit secret and public keypair.
    """
    def __init__(self, x: FQ, y: FQ, y_g1: G1):
        self.psk = x
        self.ssk = (y, y_g1)

class SchnorrKeyPair:
    """
    A Schnorr signature signing and verification keypair.
    """
    def __init__(self, x: FQ, y: FQ, x_g1: G1, y_g1: G1):
        self.vk = SchnorrVerificationKey(x_g1, y_g1)
        # We include in the signing key the verfication key
        self.sk = SchnorrSigningKey(x, y, y_g1)


def key_gen() -> SchnorrKeyPair:
    key_size_byte = ceil(len("{0:b}".format(constants.ZETH_PRIME)) / 8)
    x = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % constants.ZETH_PRIME)
    y = FQ(
        int(bytes(urandom(key_size_byte)).hex(), 16) % constants.ZETH_PRIME)
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)
    return SchnorrKeyPair(x, y, X, Y)

def gen_vk(sk: SchnorrSigningKey) -> SchnorrVerificationKey:
    x = sk.psk
    y, _ = sk.ssk
    X = ec.multiply(ec.G1, x.n)
    Y = ec.multiply(ec.G1, y.n)
    return SchnorrVerificationKey(X, Y)


def encode_group_element(group_el: G1) -> bytes:
    res = encode_abi(
        ["bytes32", "bytes32"],
        [
            bytes.fromhex("{0:0>64X}".format(int(group_el[0]))),
            bytes.fromhex("{0:0>64X}".format(int(group_el[1])))
        ]
    )
    return res


def encode_vk(vk: SchnorrVerificationKey) -> bytes:
    vk_byte = encode_group_element(vk.ppk)
    vk_byte += encode_group_element(vk.spk)
    return vk_byte


def sign(
        sk: SchnorrSigningKey,
        m: str) -> int:
    """
    Generate a Schnorr signature on a hash.
    We chose to sign the hash of the proof for modularity (to
    use the same code regardless of whether GROTH16 or PGHR13 proof system is
    chosen), and sign the hash of the ciphers and inputs for consistency.
    """

    # Encode and hash the verifying key and input hashes
    challenge_to_hash = encode_group_element(sk.ssk[1]) + encode_single("bytes32", bytes.fromhex(m))

    # Convert the hex digest into a field element
    challenge = int(sha256(challenge_to_hash).hexdigest(), 16) % constants.ZETH_PRIME

    # Compute the signature sigma
    sigma = (sk.ssk[0].n + challenge * sk.psk.n) % constants.ZETH_PRIME

    return sigma

def verify(
    vk: SchnorrVerificationKey,
    m: str,
    sigma: int) -> bool:

    # Encode and hash the verifying key and input hashes
    challenge_to_hash = encode_group_element(vk.spk) + encode_single("bytes32", bytes.fromhex(m))

    challenge = int(sha256(challenge_to_hash).hexdigest(), 16) % constants.ZETH_PRIME

    left_part = ec.multiply(ec.G1, FQ(sigma).n)
    right_part = ec.add(vk.spk, ec.multiply(vk.ppk, FQ(challenge).n))

    return ec.eq(left_part, right_part)

def test_all() -> None:
    m = urandom(32).hex()
    keypair = key_gen()
    sigma = sign(keypair.sk, m)
    assert verify(keypair.vk, m, sigma)
