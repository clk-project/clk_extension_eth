#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

import click
from cached_property import cached_property
from clk.config import config
from clk.core import run
from clk.decorators import argument, flag, group, option
from clk.lib import json_dumps, parsedatetime
from clk.log import get_logger
from clk.types import DynamicChoice
from eth_account import Account
from eth_utils import to_wei
from eth_utils.units import units
from hexbytes.main import HexBytes
from web3 import Web3
from web3.datastructures import AttributeDict

LOGGER = get_logger(__name__)


class DecimalType(click.ParamType):

    def convert(self, value, param, ctx):
        try:
            return Decimal(value)
        except InvalidOperation:
            raise click.UsageError(
                f"{param.name}: Expected a decimal number, got {value}")


class ContractMethod:
    args = []

    @cached_property
    def abi(self):
        return [
            method for method in config.eth.abi
            if method.get("name") == self.function
        ][0]

    @cached_property
    def inputs(self):
        return self.abi["inputs"]

    @cached_property
    def outputs(self):
        return self.abi.get("outputs")

    @property
    def needed_names(self):
        return {input["name"] for input in self.inputs if input["name"]}

    @property
    def given_names(self):
        return set(self._kwargs)

    @property
    def missing_names(self):
        return self.needed_names - self.given_names

    def check(self):
        missing_names = self.missing_names
        if missing_names:
            LOGGER.error(
                f"You need to provide values for {', '.join(missing_names)}")
            return False
        return True

    @property
    def _args(self):
        return [arg for arg in self.args if not isinstance(arg, dict)]

    @property
    def _kwargs(self):
        kwargs = {}
        for arg in [arg for arg in self.args if isinstance(arg, dict)]:
            kwargs.update(arg)
        return kwargs

    def coerce(self, output):
        if self.outputs:
            type = self.outputs[0]["type"]
            if type == "bytes32":
                output = f"0x{output.hex()}"
        return output

    def call(self):
        return self.coerce(
            getattr(config.eth.contract.caller, self.function)(*self._args,
                                                               **self._kwargs))

    def transact(self):
        caller = getattr(config.eth.contract.functions,
                         self.function)(*self._args, **self._kwargs)
        tx_hash = caller.transact()
        return config.eth.w3.eth.wait_for_transaction_receipt(tx_hash)


class Eth:

    def __init__(self):
        self.proof_of_authority = None

    def walk_blocks(self):
        b = self.w3.eth.get_block('latest')
        while b:
            yield b
            b_hash = b.get('parentHash')
            if b_hash == HexBytes('0x000000000000000000000000000000'
                                  '0000000000000000000000000000000000'):
                break
            else:
                b = self.w3.eth.get_block(b_hash)

    def walk_transactions(self, limit=None):
        accum = 0
        for block in self.walk_blocks():
            txs = [
                self.w3.eth.wait_for_transaction_receipt(hash)
                for hash in block.transactions
            ]
            yield from txs
            accum += len(txs)
            if limit and accum >= limit:
                break

    @property
    def myaddress(self):
        return self.account.address

    def history(self, address, limit=None):
        return (
            tx for tx in self.walk_transactions(limit=limit)
            if address in [tx.get("contractAddress"), tx["from"], tx["to"]])

    def myhistory(self, limit=None):
        yield from self.history(address=self.myaddress, limit=limit)

    def filter_contract(self, history=None):
        yield from (tx for tx in (history or self.myhistory())
                    if tx["contractAddress"])

    def take_contracts(self, history=None):
        yield from (
            tx["contractAddress"]
            for tx in self.filter_contract(history or self.myhistory()))

    @cached_property
    def abi(self):
        return json.loads(self.abi_path.read_text())["abi"]

    @property
    def account(self):
        Account.enable_unaudited_hdwallet_features()
        return Account.from_mnemonic(
            self.mnemonic,
            account_path=f"m/44'/60'/0'/0/{self.account_number}")

    @property
    def w3(self) -> Web3:
        w3 = Web3(Web3.HTTPProvider(self.url))
        from web3.middleware import construct_sign_and_send_raw_middleware

        w3.middleware_onion.add(
            construct_sign_and_send_raw_middleware(self.account))
        if self.proof_of_authority is not False or any(
                part in self.url for part in ["polygon"]):
            from web3.middleware import geth_poa_middleware
            w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        w3.eth.default_account = self.account.address
        return w3

    @cached_property
    def contract(self):
        return self.w3.eth.contract(self.address, abi=self.abi)


class ContractCaller(DynamicChoice):

    def choices(self):
        return [
            fct for fct in dir(config.eth.contract.caller)
            if not fct.startswith("__") and fct not in {"address", "abi"}
        ]


class ContractCallerArgs(DynamicChoice):
    number = 0

    def choices(self):
        return [name + "=" for name in config.contractmethod.missing_names]

    def coerce(self, key, val):
        if key:
            inp = [
                input for input in config.contractmethod.inputs
                if input["name"] == key
            ][0]
        else:
            inp = config.contractmethod.inputs[self.number - 1]
            key = inp["name"]
        if inp["type"].endswith("[]"):
            val = json.loads(val)
        elif inp["type"].startswith("uint"):
            val = int(val)
        elif inp["type"] == "bool":
            val = val in ("true", "True", "1", "t", "yes")
        elif inp["type"].startswith("byte"):
            if val.startswith("0x"):
                val = bytes.fromhex(val[2:])
            else:
                val = config.eth.w3.to_bytes(text=val)

        return key, val

    def convert(self, value, param, ctx):
        self.number += 1
        if "=" in value:
            key, val = value.split("=")
            key, val = self.coerce(key, val)
        else:
            key, val = self.coerce("", value)
        if key:
            return {key: val}
        else:
            return val


@group()
@option(
    "--mnemonic",
    expose_class=Eth,
    help="The mnemonic to use",
    default=("test test test test test test test test test test test junk"),
)
@option(
    "--account-number",
    type=int,
    expose_class=Eth,
    help=("The account to use,"
          " converted into the path m/44'/60'/0'/0/{account}"),
    default=0,
)
@option(
    "--url",
    expose_class=Eth,
    help="Url to connect to the node",
    default="http://127.0.0.1:8545",
)
@flag("--proof-of-authority",
      expose_class=Eth,
      help="Deal with Polygon, BNB, geth --dev or Goerli")
def eth():
    "Play with some web3 stuff"


@eth.command()
@flag("--human", help="Show a human representation")
def last_block_timestamp(human):
    "Show the time of the last block of the chain"
    res = next(config.eth.walk_blocks()).timestamp
    if human:
        res = datetime.fromtimestamp(res)
    print(res)


@eth.group()
def evm():
    "Commands to discuss directly with the evm"


@evm.command()
@argument("duration", help="How many seconds to add", type=int)
@flag("--and-mine/--dont-mine", help="Also mine an empty block", default=True)
def increaseTime(duration, and_mine):
    """Call this rpc method, incrementing the time

    See https://docs.nethereum.com/en/latest/ethereum-and-clients/ganache-cli/."""
    click.echo(
        json_dumps(
            config.eth.w3.provider.make_request("evm_increaseTime",
                                                [duration])))
    if and_mine:
        run(["eth", "evm", "mine"])


@evm.command()
@argument("time", help="Move to the given time")
@flag("--and-mine/--dont-mine", help="Also mine an empty block", default=True)
def move_to_time(time, and_mine):
    """Increase the evm time so that we reach the given time."""
    time: datetime = parsedatetime(time)[0]
    blockchain_time = next(config.eth.walk_blocks()).timestamp
    duration = int(time.timestamp() - blockchain_time)
    if duration < 0:
        raise click.UsageError(
            "Current blockchain time"
            f" {datetime.fromtimestamp(blockchain_time)}"
            f" is already in the future of the given time {time}.")
    args = ["eth", "evm", "increaseTime", str(duration)]
    if and_mine:
        args += ["--and-mine"]
    else:
        args += ["--dont-mine"]
    run(args)


@evm.command()
def mine():
    """Call this rpc method, creating a new block

    See https://docs.nethereum.com/en/latest/ethereum-and-clients/ganache-cli/."""
    click.echo(json_dumps(config.eth.w3.provider.make_request("evm_mine", [])))


@eth.command()
@argument("address", help="The address to transform")
def to_checksum_address(address):
    "Print the checksum valid representation of this address"
    print(Web3.to_checksum_address(address))


@eth.command()
def ipython():
    "Run ipython with everything initialized"
    e = config.eth
    w = e.w3
    eth = w.eth
    import IPython
    IPython.start_ipython(argv=[], user_ns=(globals() | locals()))


@eth.group()
@option(
    "--abi-path",
    help="The abi to interract with the contract",
    expose_class=Eth,
    type=Path,
    required=True,
)
@option(
    "--address",
    help="The address of the contract",
    required=True,
    expose_class=Eth,
)
def contract():
    "Play with a contract"


@contract.command()
def _address():
    "Dump the address of the contract"
    print(config.eth.contract.address)


@contract.command()
def _ipython():
    "Repl to discuss with this contract"
    c = config.eth.contract
    e = config.eth
    w = e.w3
    eth = w.eth
    import IPython
    IPython.start_ipython(argv=[], user_ns=(globals() | locals()))


def serializable_dict(data):
    return {
        make_serializable(key): make_serializable(value)
        for key, value in data.items()
    }


def make_serializable(data):
    if isinstance(data, AttributeDict) or isinstance(data, dict):
        return serializable_dict(data)
    elif isinstance(data, HexBytes):
        return data.hex()
    elif isinstance(data, list):
        return [make_serializable(elem) for elem in data]
    else:
        return data


@contract.command()
@argument("function",
          help="The function to call",
          type=ContractCaller(),
          expose_class=ContractMethod)
@argument(
    "args",
    help="The function to call",
    type=ContractCallerArgs(),
    expose_class=ContractMethod,
    nargs=-1,
)
@flag("--transact/--no-transact",
      help=("Also send (and pay for) the transaction."
            " Guessing the default depending on whether"
            " you are calling a view or not"),
      default=None)
def _call(transact):
    "Call a smartcontract"
    if not config.contractmethod.check():
        exit(1)
    if transact is None:
        transact = config.contractmethod.abi["stateMutability"] != "view"
    else:
        transact = transact and (
            config.contractmethod.abi["stateMutability"] != "view"
            or click.confirm("Transacting a view. Are you sure?"))

    if transact:
        hash = config.contractmethod.transact()
        print(json_dumps(make_serializable(hash)))
    else:
        print(config.contractmethod.call())


@contract.command()
def abi():
    "Dump the abi of the contract"
    print(json_dumps(config.eth.abi))


@eth.command()
def _address():
    "Show my address"
    print(config.eth.myaddress)


@eth.command()
def _addresses():
    "Show my addresses"
    print("\n".join(config.eth.w3.eth.accounts))


@eth.command()
def created_contracts():
    "List contracts I created"
    print("\n".join(list(config.eth.take_contracts())))


@eth.command()
@argument("address")
def history(address):
    for history_ in config.eth.history(address):
        print(json_dumps(make_serializable(history_)))


@eth.command()
@argument("to", help="Address that will receive the value")
@argument("amount", help="How much to send", type=DecimalType())
@argument("unit",
          help="What unit to use",
          type=click.Choice(units),
          default="wei")
def send(to, amount, unit):
    "Send some value to some address"
    eth: Eth = config.eth
    result = eth.w3.eth.send_transaction({
        "from": eth.myaddress,
        "to": to,
        "value": to_wei(amount, unit)
    })
    click.echo(result.hex())


@eth.command()
def generate_mnemonic():
    "Generate a private key to play with"
    from mnemonic import Mnemonic
    m = Mnemonic("english")
    words = m.generate()
    print(words)
