# Python client to interact with the prover

## Setup

Ensure that the following are installed:

- Python 3.7 (See `python --version`)
- [venv](https://docs.python.org/3/library/venv.html#module-venv) module.
- gcc

```console
$ python -m venv env
$ source env/bin/activate
(env)$ make setup
```

## Execute unit tests

```console
(env)$ make check
```

## Execute testing client

Test ether mixing:
```console
test_ether_mixing.py [ZKSNARK]
```

Test ERC token mixing
```console
test_erc_token_mixing.py [ZKSNARK]
```

where `[ZKSNARK]` is the zksnark to use (must be the same as the one used on
the server).

## Note on solc compiler installation

Note that `make setup` will automatically install solidity compiler in `$HOME$/.solc`
(if required) and not in the python virtual environment.
