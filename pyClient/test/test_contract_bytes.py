#!/usr/bin/env python3
import zeth.constants as constants

import os
from solcx import compile_files  # type: ignore
from web3 import Web3, HTTPProvider  # type: ignore

W3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
eth = W3.eth  # pylint: disable=no-member,invalid-name


def main() -> None:
    print("-------------------- Evaluating Bytes.sol --------------------")
    contracts_dir = os.environ['ZETH_CONTRACTS_DIR']
    path_to_bytes = os.path.join(contracts_dir, "Bytes.sol")
    path_to_bytes_tests = os.path.join(contracts_dir, "Bytes_tests.sol")
    compiled_sol = compile_files([path_to_bytes, path_to_bytes_tests])
    bytes_interface = compiled_sol[path_to_bytes_tests + ':' + "Bytes_tests"]
    contract = eth.contract(
        abi=bytes_interface['abi'],
        bytecode=bytes_interface['bin'])
    tx_hash = contract.constructor().transact({'from': eth.accounts[1]})
    tx_receipt = eth.waitForTransactionReceipt(tx_hash, 100000)
    address = tx_receipt['contractAddress']
    bytes_instance = eth.contract(address=address, abi=bytes_interface['abi'])

    result = 1

    print("--- testing ", "testReverseByte")
    test_reverse_byte = bytes_instance.functions.testReverseByte().call()
    if not test_reverse_byte:
        print("testReverseByte FAILS")
        result *= 0

    print("--- testing ", "testGetLastByte")
    test_get_last_byte = bytes_instance.functions.testGetLastByte().call()
    if not test_get_last_byte:
        print("testGetLastByte FAILS")
        result *= 0

    print("--- testing ", "testFlipEndiannessBytes32")
    test_flip_endianness_bytes32 = \
        bytes_instance.functions.testFlipEndiannessBytes32().call()
    if not test_flip_endianness_bytes32:
        print("testFlipEndiannessBytes32 FAILS")
        result *= 0

    print("--- testing ", "testBytesToBytes32")
    test_bytes_to_bytes32 = \
        bytes_instance.functions.testBytesToBytes32().call()
    if not test_bytes_to_bytes32:
        print("testBytesToBytes32 FAILS")
        result *= 0

    print("--- testing ", "testSha256DigestFromFieldElements")
    test_sha256_digest_from_field_elements = \
        bytes_instance.functions.testSha256DigestFromFieldElements().call()
    if not test_sha256_digest_from_field_elements:
        print("testSha256DigestFromFieldElements FAILS")
        result *= 0

    print("--- testing ", "testSwapBitOrder")
    test_swap_bit_order = bytes_instance.functions.testSwapBitOrder().call()
    if not test_swap_bit_order:
        print("testSwapBitOrder FAILS")
        result *= 0

    if result:
        print("All Bytes tests PASS")


if __name__ == '__main__':
    main()
