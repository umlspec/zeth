#!/usr/bin/env python3

# Copyright (c) 2015-2019 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

import zeth.joinsplit as joinsplit
import zeth.contracts as contracts
from zeth.constants import ZETH_PRIME
import zeth.signing as signing
from zeth.utils import EtherValue, compute_merkle_path
import test_commands.mock as mock
import api.util_pb2 as util_pb2

from os import urandom
from web3 import Web3  # type: ignore
from typing import List, Tuple, Optional

ZERO_UNITS_HEX = "0000000000000000"
BOB_DEPOSIT_ETH = 200
BOB_SPLIT_1_ETH = 100
BOB_SPLIT_2_ETH = 100

BOB_TO_CHARLIE_ETH = 50
BOB_TO_CHARLIE_CHANGE_ETH = BOB_SPLIT_1_ETH - BOB_TO_CHARLIE_ETH

CHARLIE_WITHDRAW_ETH = 10.5
CHARLIE_WITHDRAW_CHANGE_ETH = 39.5


def dump_merkle_tree(mk_tree: List[bytes]) -> None:
    print("[DEBUG] Displaying the Merkle tree of commitments: ")
    for node in mk_tree:
        print("Node: " + Web3.toHex(node)[2:])


def bob_deposit(
        zeth_client: joinsplit.ZethClient,
        bob_eth_address: str,
        keystore: mock.KeyStore,
        tx_value: Optional[EtherValue] = None) -> contracts.MixResult:
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and splits into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH ===")

    bob_js_keypair = keystore["Bob"]
    bob_addr = keystore["Bob"].addr_pk

    outputs = [
        (bob_addr, EtherValue(BOB_SPLIT_1_ETH)),
        (bob_addr, EtherValue(BOB_SPLIT_2_ETH)),
    ]

    mk_tree = zeth_client.get_merkle_tree()
    return zeth_client.wait(zeth_client.deposit(
        mk_tree,
        bob_js_keypair,
        bob_eth_address,
        EtherValue(BOB_DEPOSIT_ETH),
        outputs,
        tx_value))


def bob_to_charlie(
        zeth_client: joinsplit.ZethClient,
        input1: Tuple[int, util_pb2.ZethNote],
        bob_eth_address: str,
        keystore: mock.KeyStore) -> contracts.MixResult:
    print(
        f"=== Bob transfers {BOB_TO_CHARLIE_ETH}ETH to Charlie from his funds " +
        "on the mixer ===")

    bob_ask = keystore["Bob"].addr_sk.a_sk
    charlie_addr = keystore["Charlie"].addr_pk
    bob_addr = keystore["Bob"].addr_pk

    # Coin for Bob (change)
    output0 = (bob_addr, EtherValue(BOB_TO_CHARLIE_ETH))
    # Coin for Charlie
    output1 = (charlie_addr, EtherValue(BOB_TO_CHARLIE_CHANGE_ETH))

    # Send the tx
    mk_tree = zeth_client.get_merkle_tree()
    return zeth_client.wait(zeth_client.joinsplit(
        mk_tree,
        joinsplit.OwnershipKeyPair(bob_ask, bob_addr.a_pk),
        bob_eth_address,
        [input1],
        [output0, output1],
        EtherValue(0),
        EtherValue(0),
        EtherValue(1, 'wei')))


def charlie_withdraw(
        zeth_client: joinsplit.ZethClient,
        input1: Tuple[int, util_pb2.ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> contracts.MixResult:
    print(
        f" === Charlie withdraws {CHARLIE_WITHDRAW_ETH}ETH from his funds " +
        "on the Mixer ===")

    mk_tree = zeth_client.get_merkle_tree()
    charlie_pk = keystore["Charlie"].addr_pk
    charlie_apk = charlie_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk
    charlie_ownership_key = \
        joinsplit.OwnershipKeyPair(charlie_ask, charlie_apk)

    return zeth_client.wait(zeth_client.joinsplit(
        mk_tree,
        charlie_ownership_key,
        charlie_eth_address,
        [input1],
        [(charlie_pk, EtherValue(CHARLIE_WITHDRAW_CHANGE_ETH))],
        EtherValue(0),
        EtherValue(CHARLIE_WITHDRAW_ETH),
        EtherValue(1, 'wei')))


def charlie_double_withdraw(
        zeth_client: joinsplit.ZethClient,
        input1: Tuple[int, util_pb2.ZethNote],
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> contracts.MixResult:
    """
    Charlie tries to carry out a double spending by modifying the value of the
    nullifier of the previous payment
    """
    print(
        f" === Charlie attempts to withdraw {CHARLIE_WITHDRAW_ETH}ETH once " +
        "more (double spend) one of his note on the Mixer ===")

    charlie_apk = keystore["Charlie"].addr_pk.a_pk
    charlie_ask = keystore["Charlie"].addr_sk.a_sk

    mk_byte_tree = zeth_client.get_merkle_tree()
    mk_tree_depth = zeth_client.mk_tree_depth
    mk_root = zeth_client.merkle_root
    mk_path1 = compute_merkle_path(input1[0], mk_tree_depth, mk_byte_tree)

    # Create the an additional dummy input for the JoinSplit
    input2 = joinsplit.get_dummy_input_and_address(charlie_apk)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = joinsplit.to_zeth_units(EtherValue(CHARLIE_WITHDRAW_CHANGE_ETH))
    v_out = EtherValue(CHARLIE_WITHDRAW_ETH)

    # ### ATTACK BLOCK
    # Add malicious nullifiers: we reuse old nullifiers to double spend by
    # adding $r$ to them so that they have the same value as before in Z_r,
    # and so the zksnark verification passes, but have different values in
    # {0;1}^256 so that they appear different to the contract.
    # See: https://github.com/clearmatics/zeth/issues/38

    attack_primary_input1: int = 0
    attack_primary_input2: int = 0

    def compute_h_sig_attack_nf(
            nf0: bytes,
            nf1: bytes,
            sign_vk: joinsplit.JoinsplitSigVerificationKey) -> bytes:
        # We disassemble the nfs to get the formatting of the primary inputs
        input_nullifier0 = nf0.hex()
        input_nullifier1 = nf1.hex()
        nf0_rev = "{0:0256b}".format(int(input_nullifier0, 16))[::-1]
        primary_input1_bits = nf0_rev[3:]
        primary_input1_res_bits = nf0_rev[:3]
        nf1_rev = "{0:0256b}".format(int(input_nullifier1, 16))[::-1]
        primary_input2_bits = nf1_rev[3:]
        primary_input2_res_bits = nf1_rev[:3]

        # We perform the attack, recoding the modified public input values
        nonlocal attack_primary_input1
        nonlocal attack_primary_input2
        attack_primary_input1 = int(primary_input1_bits, 2) + ZETH_PRIME
        attack_primary_input2 = int(primary_input2_bits, 2) + ZETH_PRIME

        # We reassemble the nfs
        attack_primary_input1_bits = "{0:0256b}".format(attack_primary_input1)
        attack_nf0_bits = \
            primary_input1_res_bits + attack_primary_input1_bits[3:]
        attack_nf0 = "{0:064x}".format(int(attack_nf0_bits[::-1], 2))
        attack_primary_input2_bits = "{0:0256b}".format(attack_primary_input2)
        attack_nf1_bits = \
            primary_input2_res_bits + attack_primary_input2_bits[3:]
        attack_nf1 = "{0:064x}".format(int(attack_nf1_bits[::-1], 2))
        return joinsplit.compute_h_sig(
            bytes.fromhex(attack_nf0), bytes.fromhex(attack_nf1), sign_vk)

    (output_note1, output_note2, proof_json, signing_keypair) = \
        zeth_client.get_proof_joinsplit_2_by_2(
            mk_root,
            input1,
            mk_path1,
            input2,
            dummy_mk_path,
            charlie_ask,  # sender
            (charlie_apk, note1_value),  # recipient1
            (charlie_apk, 0),  # recipient2
            joinsplit.to_zeth_units(EtherValue(0)),  # v_in
            joinsplit.to_zeth_units(v_out),  # v_out
            compute_h_sig_attack_nf)

    # Update the primary inputs to the modified nullifiers, since libsnark
    # overwrites them with values in Z_p

    assert attack_primary_input1 != 0
    assert attack_primary_input2 != 0

    print("proof_json => ", proof_json)
    print("proof_json[inputs][1] => ", proof_json["inputs"][1])
    print("proof_json[inputs][2] => ", proof_json["inputs"][2])
    proof_json["inputs"][1] = hex(attack_primary_input1)
    proof_json["inputs"][2] = hex(attack_primary_input2)
    # ### ATTACK BLOCK

    # construct pk object from bytes
    pk_charlie = keystore["Charlie"].addr_pk.k_pk

    # encrypt the coins
    (sender_eph_pk, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_charlie),
        (output_note2, pk_charlie)])

    # Compute the joinSplit signature
    joinsplit_sig = joinsplit.joinsplit_sign(
        signing_keypair, sender_eph_pk, ciphertexts, proof_json)

    return zeth_client.wait(zeth_client.mix(
        sender_eph_pk,
        ciphertexts[0],
        ciphertexts[1],
        proof_json,
        signing_keypair.vk,
        joinsplit_sig,
        charlie_eth_address,
        # Pay an arbitrary amount (1 wei here) that will be refunded since the
        # `mix` function is payable
        Web3.toWei(1, 'wei'),
        4000000))


def charlie_corrupt_bob_deposit(
        zeth_client: joinsplit.ZethClient,
        bob_eth_address: str,
        charlie_eth_address: str,
        keystore: mock.KeyStore) -> contracts.MixResult:
    """
    Charlie tries to break transaction malleability and corrupt the coins
    bob is sending in a transaction
    She does so by intercepting bob's transaction and either:
    - case 1: replacing the ciphertexts (or pk_sender) by garbage/arbitrary data
    - case 2: replacing the ciphertexts by garbage/arbitrary data and using a
    new OT-signature
    Both attacks should fail,
    - case 1: the signature check should fail, else Charlie broke UF-CMA
        of the OT signature
    - case 2: the h_sig/vk verification should fail, as h_sig is not a function
        of vk any longer
    NB. If the adversary were to corrupt the ciphertexts (or the encryption key),
    replace the OT-signature by a new one and modify the h_sig accordingly so that
    the check on the signature verification (key h_sig/vk) passes, the proof would
    not verify, which is why we do not test this case.
    """
    print(
        f"=== Bob deposits {BOB_DEPOSIT_ETH} ETH for himself and split into " +
        f"note1: {BOB_SPLIT_1_ETH}ETH, note2: {BOB_SPLIT_2_ETH}ETH" +
        f"but Charlie attempts to corrupt the transaction ===")
    bob_apk = keystore["Bob"].addr_pk.a_pk
    bob_ask = keystore["Bob"].addr_sk.a_sk
    mk_tree_depth = zeth_client.mk_tree_depth
    mk_root = zeth_client.merkle_root

    # Create the JoinSplit dummy inputs for the deposit
    input1 = joinsplit.get_dummy_input_and_address(bob_apk)
    input2 = joinsplit.get_dummy_input_and_address(bob_apk)
    dummy_mk_path = mock.get_dummy_merkle_path(mk_tree_depth)

    note1_value = joinsplit.to_zeth_units(EtherValue(BOB_SPLIT_1_ETH))
    note2_value = joinsplit.to_zeth_units(EtherValue(BOB_SPLIT_2_ETH))

    v_in = joinsplit.to_zeth_units(EtherValue(BOB_DEPOSIT_ETH))

    (output_note1, output_note2, proof_json, joinsplit_keypair) = \
        zeth_client.get_proof_joinsplit_2_by_2(
            mk_root,
            input1,
            dummy_mk_path,
            input2,
            dummy_mk_path,
            bob_ask,  # sender
            (bob_apk, note1_value),  # recipient1
            (bob_apk, note2_value),  # recipient2
            v_in,  # v_in
            joinsplit.to_zeth_units(EtherValue(0))  # v_out
        )

    # Encrypt the coins to bob
    pk_bob = keystore["Bob"].addr_pk.k_pk
    (pk_sender, ciphertexts) = joinsplit.encrypt_notes([
        (output_note1, pk_bob),
        (output_note2, pk_bob)])

    # Sign the primary inputs, pk_sender and the ciphertexts
    joinsplit_sig = joinsplit.joinsplit_sign(
        joinsplit_keypair,
        pk_sender,
        ciphertexts,
        proof_json
    )

    # ### ATTACK BLOCK
    # Charlie intercepts Bob's deposit, corrupts it and
    # sends her transaction before Bob's transaction is accepted

    # Case 1: replacing the ciphertexts by garbage/arbitrary data
    # Corrupt the ciphertexts
    # (another way would have been to overwrite pk_sender)
    fake_ciphertext0 = urandom(32)
    fake_ciphertext1 = urandom(32)

    result_corrupt1 = None
    try:
        result_corrupt1 = zeth_client.wait(zeth_client.mix(
            pk_sender,
            fake_ciphertext0,
            fake_ciphertext1,
            proof_json,
            joinsplit_keypair.vk,
            joinsplit_sig,
            charlie_eth_address,
            # Pay an arbitrary amount (1 wei here) that will be refunded
            #  since the `mix` function is payable
            Web3.toWei(BOB_DEPOSIT_ETH, 'ether'),
            4000000))
    except Exception as e:
        print(
            f"Charlie's first corruption attempt" +
            f" successfully rejected! (msg: {e})"
        )
    assert(result_corrupt1 is None), \
        "Charlie managed to corrupt Bob's deposit the first time!"
    print("")

    # Case 2: replacing the ciphertexts by garbage/arbitrary data and
    # using a new OT-signature
    # Corrupt the ciphertexts
    fake_ciphertext0 = urandom(32)
    fake_ciphertext1 = urandom(32)
    new_joinsplit_keypair = signing.gen_signing_keypair()

    # Sign the primary inputs, pk_sender and the ciphertexts
    new_joinsplit_sig = joinsplit.joinsplit_sign(
        new_joinsplit_keypair,
        pk_sender,
        [fake_ciphertext0, fake_ciphertext1],
        proof_json
    )

    result_corrupt2 = None
    try:
        result_corrupt2 = zeth_client.wait(zeth_client.mix(
            pk_sender,
            fake_ciphertext0,
            fake_ciphertext1,
            proof_json,
            new_joinsplit_keypair.vk,
            new_joinsplit_sig,
            charlie_eth_address,
            # Pay an arbitrary amount (1 wei here) that will be refunded since the
            # `mix` function is payable
            Web3.toWei(BOB_DEPOSIT_ETH, 'ether'),
            4000000))
    except Exception as e:
        print(
            f"Charlie's second corruption attempt" +
            f" successfully rejected! (msg: {e})"
        )
    assert(result_corrupt2 is None), \
        "Charlie managed to corrupt Bob's deposit the second time!"

    # ### ATTACK BLOCK

    # Bob transaction is finally mined
    return zeth_client.wait(zeth_client.mix(
        pk_sender,
        ciphertexts[0],
        ciphertexts[1],
        proof_json,
        joinsplit_keypair.vk,
        joinsplit_sig,
        bob_eth_address,
        Web3.toWei(BOB_DEPOSIT_ETH, 'ether'),
        4000000))
