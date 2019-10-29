import json
import os
import sys
import argparse

from web3 import Web3, HTTPProvider, IPCProvider, WebsocketProvider
from solcx import compile_standard, compile_files

# Get the utils to deploy and call the contracts
import zethContracts
# Get the utils written to interact with the prover
import zethGRPC
# Get the mock data for the test
import zethMock
# Get the utils to encrypt/decrypt
import zethUtils
# Get the test scenario
import zethTestScenario as zethTest
# Get the zeth constants
import zethConstants as constants

w3 = Web3(HTTPProvider(constants.WEB3_HTTP_PROVIDER))
test_grpc_endpoint = constants.RPC_ENDPOINT

# Compile the testing ERC20 token contract
def compile_token():
    zeth_dir = os.environ['ZETH']
    allowed_path = os.path.join(zeth_dir, "zeth-contracts/node_modules/openzeppelin-solidity/contracts")
    path_to_token = os.path.join(zeth_dir, "zeth-contracts/node_modules/openzeppelin-solidity/contracts/token/ERC20/ERC20Mintable.sol")
    # Compilation
    compiled_sol = compile_files([path_to_token], allow_paths=allowed_path)
    token_interface = compiled_sol[path_to_token +":ERC20Mintable"]
    return token_interface

# Deploy the testing ERC20 token contract
def deploy_token(deployer_address, deployment_gas):
    token_interface = compile_token()
    token = w3.eth.contract(abi=token_interface['abi'], bytecode=token_interface['bin'])
    tx_hash = token.constructor().transact({'from': deployer_address, 'gas': deployment_gas})
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

    token = w3.eth.contract(
        address=tx_receipt.contractAddress,
        abi=token_interface['abi'],
    )
    return token

def get_merkle_tree(mixer_instance):
    mk_byte_tree = mixer_instance.functions.getTree().call()
    print("[DEBUG] Displaying the Merkle tree of commitments: ")
    for node in mk_byte_tree:
        print("Node: " + w3.toHex(node)[2:])
    return mk_byte_tree

def print_token_balances(bob, alice, charlie, mixer):
    print("Alice's Token balance: {}".format(token_instance.functions.balanceOf(alice).call()))
    print("Bob's Token balance: {}".format(token_instance.functions.balanceOf(bob).call()))
    print("Charlie's Token balance: {}".format(token_instance.functions.balanceOf(charlie).call()))
    print("Mixer's Token balance: {}".format(token_instance.functions.balanceOf(mixer).call()))

def approve(token_instance, owner_address, spender_address, token_amount):
    return token_instance.functions.approve(spender_address, w3.toWei(token_amount, 'ether')).transact({'from': owner_address})

def allowance(token_instance, owner_address, spender_address):
    return token_instance.functions.allowance(owner_address, spender_address).call()

def mint_token(token_instance, spender_address, deployer_address, token_amount):
    return token_instance.functions.mint(spender_address, w3.toWei(token_amount, 'ether')).transact({'from': deployer_address})

if __name__ == '__main__':
    zksnark = zethUtils.parse_zksnark_arg()

    # Ethereum addresses
    deployer_eth_address = w3.eth.accounts[0]
    bob_eth_address = w3.eth.accounts[1]
    alice_eth_address = w3.eth.accounts[2]
    charlie_eth_address = w3.eth.accounts[3]
    # Zeth addresses
    keystore = zethMock.initTestKeystore()
    # Depth of the merkle tree (need to match the one used in the cpp prover)
    mk_tree_depth = constants.ZETH_MERKLE_TREE_DEPTH

    print("[INFO] 1. Fetching the verification key from the proving server")
    vk = zethGRPC.getVerificationKey(test_grpc_endpoint)

    print("[INFO] 2. Received VK, writing the key...")
    zethGRPC.writeVerificationKey(vk, zksnark)

    print("[INFO] 3. VK written, deploying the smart contracts...")
    token_interface = compile_token()
    (proof_verifier_interface, otsig_verifier_interface, mixer_interface) = zethContracts.compile_contracts(zksnark)
    hasher_interface, _ = zethContracts.compile_util_contracts()
    token_instance = deploy_token(deployer_eth_address, 4000000)
    (mixer_instance, initial_root) = zethContracts.deploy_contracts(
        mk_tree_depth,
        proof_verifier_interface,
        otsig_verifier_interface,
        mixer_interface,
        hasher_interface,
        deployer_eth_address,
        4000000,
        token_instance.address, # We mix Ether in this test, so we set the addr of the ERC20 contract to be 0x0
        zksnark
    )

    print("[INFO] 4. Running tests (asset mixed: ERC20 token)...")
    # We assign ETHToken to Bob
    mint_token(
        token_instance,
        bob_eth_address,
        deployer_eth_address,
        zethTest.BOB_DEPOSIT_ETH)
    print("- Initial balances: ")
    print_token_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Bob tries to deposit ETHToken, split in 2 notes on the mixer (without approving)
    try:
        result_deposit_bob_to_bob = zethTest.bob_deposit(
            test_grpc_endpoint,
            mixer_instance,
            initial_root,
            bob_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        allowance_mixer =  allowance(token_instance, bob_eth_address, mixer_instance.address)
        print("[ERROR] Bob deposit failed! (msg: {})".format(e))
        print("The allowance for Mixer from Bob is: ", allowance_mixer)

    # Bob approves the transfer
    print("- Bob approves the transfer of ETHToken to the Mixer")
    tx_hash = approve(
        token_instance,
        bob_eth_address,
        mixer_instance.address,
        zethTest.BOB_DEPOSIT_ETH)
    w3.eth.waitForTransactionReceipt(tx_hash)
    allowance_mixer = allowance(token_instance, bob_eth_address, mixer_instance.address)
    print("- The allowance for the Mixer from Bob is:", allowance_mixer)
    # Bob deposits ETHToken, split in 2 notes on the mixer
    result_deposit_bob_to_bob = zethTest.bob_deposit(
        test_grpc_endpoint,
        mixer_instance,
        initial_root,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )
    cm_address_bob_to_bob1 = result_deposit_bob_to_bob[0]
    cm_address_bob_to_bob2 = result_deposit_bob_to_bob[1]
    new_merkle_root_bob_to_bob = result_deposit_bob_to_bob[2]
    pk_sender_bob_to_bob = result_deposit_bob_to_bob[3]
    ciphertext_bob_to_bob1 = result_deposit_bob_to_bob[4]
    ciphertext_bob_to_bob2 = result_deposit_bob_to_bob[5]

    print("- Balances after Bob's deposit: ")
    print_token_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Construct sk and pk objects from bytes
    alice_sk = zethUtils.get_private_key_from_bytes(keystore["Alice"]["AddrSk"]["encSK"])
    pk_sender = zethUtils.get_public_key_from_bytes(pk_sender_bob_to_bob)

    # Alice sees a deposit and tries to decrypt the ciphertexts to see if she was the recipient
    # But she wasn't the recipient (Bob was), so she fails to decrypt
    recovered_plaintext1 = zethUtils.receive(ciphertext_bob_to_bob1, pk_sender, alice_sk, "alice")
    recovered_plaintext2 = zethUtils.receive(ciphertext_bob_to_bob2, pk_sender, alice_sk, "alice")
    assert (recovered_plaintext1 == ""),"Alice managed to decrypt a ciphertext that was not encrypted with her key!"
    assert (recovered_plaintext2 == ""),"Alice managed to decrypt a ciphertext that was not encrypted with her key!"

    # Bob does a transfer of ETHToken to Charlie on the mixer
    #
    # Bob looks in the merkle tree and gets the merkle path to the commitment he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zethUtils.compute_merkle_path(cm_address_bob_to_bob1, mk_tree_depth, mk_byte_tree)
    # Bob decrypts one of the note he previously received (useless here but useful if the payment came from someone else)
    bob_sk = zethUtils.get_private_key_from_bytes(keystore["Bob"]["AddrSk"]["encSK"])
    input_note_json = json.loads(zethUtils.decrypt(ciphertext_bob_to_bob1, pk_sender, bob_sk))
    input_note_bob_to_charlie = zethGRPC.zethNoteObjFromParsed(input_note_json)
    # Execution of the transfer
    result_transfer_bob_to_charlie = zethTest.bob_to_charlie(
        test_grpc_endpoint,
        mixer_instance,
        new_merkle_root_bob_to_bob,
        mk_path,
        input_note_bob_to_charlie,
        cm_address_bob_to_bob1,
        bob_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )
    cm_address_bob_to_charlie1 = result_transfer_bob_to_charlie[0] # Bob -> Bob (Change)
    cm_address_bob_to_charlie2 = result_transfer_bob_to_charlie[1] # Bob -> Charlie (payment to Charlie)
    new_merkle_root_bob_to_charlie = result_transfer_bob_to_charlie[2]
    pk_sender_bob_to_charlie = result_transfer_bob_to_charlie[3]
    ciphertext_bob_to_charlie1 = result_transfer_bob_to_charlie[4]
    ciphertext_bob_to_charlie2 = result_transfer_bob_to_charlie[5]

    # Bob tries to spend `input_note_bob_to_charlie` twice
    result_double_spending = ""
    try:
        result_double_spending = zethTest.bob_to_charlie(
            test_grpc_endpoint,
            mixer_instance,
            new_merkle_root_bob_to_bob,
            mk_path,
            input_note_bob_to_charlie,
            cm_address_bob_to_bob1,
            bob_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        print("Bob's double spending successfully rejected! (msg: {})".format(e))
    assert (result_double_spending == ""),"Bob managed to spend the same note twice!"

    print("- Balances after Bob's transfer to Charlie: ")
    print_token_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Construct sk and pk objects from bytes
    charlie_sk = zethUtils.get_private_key_from_bytes(keystore["Charlie"]["AddrSk"]["encSK"])
    pk_sender = zethUtils.get_public_key_from_bytes(pk_sender_bob_to_charlie)

    # Charlie tries to decrypt the ciphertexts from Bob's previous transaction
    recovered_plaintext1 = zethUtils.receive(ciphertext_bob_to_charlie1, pk_sender, charlie_sk, "charlie")
    recovered_plaintext2 = zethUtils.receive(ciphertext_bob_to_charlie2, pk_sender, charlie_sk, "charlie")
    assert (recovered_plaintext1 == ""),"Charlie managed to decrypt a ciphertext that was not encrypted with his key!"
    assert (recovered_plaintext2 != ""),"Charlie should have been able to decrypt the ciphertext that was obtained with his key!"

    # Charlie now gets the merkle path for the commitment he wants to spend
    mk_byte_tree = get_merkle_tree(mixer_instance)
    mk_path = zethUtils.compute_merkle_path(cm_address_bob_to_charlie2, mk_tree_depth, mk_byte_tree)
    input_note_charlie_withdraw = zethGRPC.zethNoteObjFromParsed(json.loads(recovered_plaintext2))
    result_charlie_withdrawal = zethTest.charlie_withdraw(
        test_grpc_endpoint,
        mixer_instance,
        new_merkle_root_bob_to_charlie,
        mk_path,
        input_note_charlie_withdraw,
        cm_address_bob_to_charlie2,
        charlie_eth_address,
        keystore,
        mk_tree_depth,
        zksnark
    )

    new_merkle_root_charlie_withdrawal = result_charlie_withdrawal[2]
    print("- Balances after Charlie's withdrawal: ")
    print_token_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )

    # Charlie tries to carry out a double spend by withdrawing twice the same note
    result_double_spending = ""
    try:
        # New commitments are added in the tree at each withdraw so we recompiute the path to have the updated nodes
        mk_byte_tree = get_merkle_tree(mixer_instance)
        mk_path = zethUtils.compute_merkle_path(cm_address_bob_to_charlie2, mk_tree_depth, mk_byte_tree)
        result_double_spending = zethTest.charlie_double_withdraw(
            test_grpc_endpoint,
            mixer_instance,
            new_merkle_root_charlie_withdrawal,
            mk_path,
            input_note_charlie_withdraw,
            cm_address_bob_to_charlie2,
            charlie_eth_address,
            keystore,
            mk_tree_depth,
            zksnark
        )
    except Exception as e:
        print("Charlie's double spending successfully rejected! (msg: {})".format(e))
    print("Balances after Charlie's double withdrawal attempt: ")
    assert (result_double_spending == ""),"Charlie managed to withdraw the same note twice!"
    print_token_balances(
        bob_eth_address,
        alice_eth_address,
        charlie_eth_address,
        mixer_instance.address
    )