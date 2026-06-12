#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path

import click
from cached_property import cached_property
from clk.config import config
from clk.core import run, cache_disk
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

# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = ("0xddf252ad1be2c89b69c2b068fc378d"
                  "aa952ba7f163c4a11628f55a4df523b3ef")


def _read_only_w3(url):
    "A lightweight, POA-tolerant read-only web3 for the cached RPC helpers."
    w3 = Web3(Web3.HTTPProvider(url))
    from web3.middleware import ExtraDataToPOAMiddleware
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


@cache_disk(expire=3600 * 24 * 7)
def _rpc_block_timestamp(url, block_number):
    "Timestamp of a block — immutable, so safe to cache on disk for a week."
    return _read_only_w3(url).eth.get_block(block_number).timestamp


@cache_disk(expire=3600 * 24 * 7)
def _rpc_get_logs(url, address, topics, from_block, to_block):
    """eth_getLogs for one window, normalized to plain serializable dicts.

    Cached on disk so repeated runs of a command reuse a window's logs instead
    of re-hitting the node (a finalized block range's logs never change)."""
    raw = _read_only_w3(url).eth.get_logs({
        "address": Web3.to_checksum_address(address),
        "topics": topics,
        "fromBlock": from_block,
        "toBlock": to_block,
    })
    return [{
        "blockNumber": log["blockNumber"],
        "logIndex": log["logIndex"],
        "transactionHash": HexBytes(log["transactionHash"]).hex(),
        "topics": [HexBytes(topic).hex() for topic in log["topics"]],
        "data": HexBytes(log["data"]).hex(),
    } for log in raw]


class DecimalType(click.ParamType):

    def convert(self, value, param, ctx):
        try:
            return Decimal(value)
        except InvalidOperation:
            raise click.UsageError(
                f"{param.name}: Expected a decimal number, got {value}")


class AbiPath(click.ParamType):
    name = "abi-path"

    def convert(self, value, param, ctx):
        if isinstance(value, Path):
            return value
        if value.startswith("alias:"):
            alias = value[len("alias:"):]
            path = Path(__file__).parent.parent / "files" / f"{alias}.json"
            if not path.exists():
                self.fail(
                    f"Unknown abi alias {alias!r}: {path} not found",
                    param, ctx)
            return path
        return Path(value)


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
        self.private_key = None

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

    def block_timestamp(self, block_number, _cache={}):
        "Return the unix timestamp of a block (disk-cached, plus a proc memo)."
        if block_number not in _cache:
            _cache[block_number] = _rpc_block_timestamp(self.url, block_number)
        return _cache[block_number]

    def block_at_timestamp(self, timestamp):
        """Smallest block number whose timestamp is >= `timestamp`.

        Binary search over block timestamps (reusing the memoized lookup), so
        callers can express a range in wall-clock time rather than blocks."""
        target = int(timestamp)
        lo, hi = 0, self.w3.eth.block_number
        if self.block_timestamp(hi) < target:
            return hi
        while lo < hi:
            mid = (lo + hi) // 2
            if self.block_timestamp(mid) < target:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def transfer_logs(self, address, from_block, to_block):
        """Return the ERC20 Transfer events of `self.address` touching `address`.

        Performs two passes (address as the `from` and as the `to` of the
        transfer) and strides forward in windows, learning the node's max
        block range from its error message so it neither re-discovers the
        limit on every call nor fans out into a flood of split requests.
        Each window goes through the disk-cached `_rpc_get_logs`."""
        addr_topic = "0x" + address[2:].lower().rjust(64, "0")
        passes = ([TRANSFER_TOPIC, addr_topic],        # address is the sender
                  [TRANSFER_TOPIC, None, addr_topic])  # address is the receiver
        seen = set()
        merged = []
        for topics in passes:
            for log in self._scan_logs(topics, from_block, to_block):
                # a self-transfer matches both passes: dedupe on tx + log index
                key = (log["transactionHash"], log["logIndex"])
                if key in seen:
                    continue
                seen.add(key)
                merged.append({
                    "blockNumber": log["blockNumber"],
                    "logIndex": log["logIndex"],
                    "tx_hash": log["transactionHash"],
                    "from": Web3.to_checksum_address(
                        "0x" + log["topics"][1][-40:]),
                    "to": Web3.to_checksum_address(
                        "0x" + log["topics"][2][-40:]),
                    "value": int(log["data"], 16),
                })
        merged.sort(key=lambda log: (log["blockNumber"], log["logIndex"]))
        return merged

    @staticmethod
    def _parse_max_range(message):
        "Extract the node's advertised max getLogs block range, if any."
        match = re.search(r"max(?:imum)?\s+block\s+range\s+(\d+)",
                          message, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def _scan_logs(self, topics, from_block, to_block):
        """Scan [from_block, to_block] forward, one window per call.

        Windows are snapped to fixed block-number boundaries (multiples of the
        window size) rather than to `from_block`, so the same windows recur
        across invocations even when the requested range slides — letting the
        disk cache absorb everything but the moving head window. Results are
        filtered back to the exact requested range.

        Starts optimistically large; on a 'max block range' rejection it learns
        the exact window the node allows (or halves as a fallback) and remembers
        it on the instance so later windows and the second pass reuse it."""
        results = []
        cursor = from_block
        # `_log_window` is remembered across windows and passes
        step = getattr(self, "_log_window", None) or 100_000
        while cursor <= to_block:
            win_start = (cursor // step) * step  # snap to a fixed boundary
            win_end = win_start + step - 1
            try:
                logs = _rpc_get_logs(self.url, self.address, topics,
                                     win_start, min(win_end, to_block))
                results += [log for log in logs
                            if from_block <= log["blockNumber"] <= to_block]
                cursor = win_end + 1
            except Exception as e:
                advertised = self._parse_max_range(str(e))
                if advertised is not None and advertised < step:
                    step = advertised
                elif step > 1:
                    step = step // 2
                else:
                    raise
                self._log_window = step
                LOGGER.debug(
                    f"Narrowed getLogs window to {step} blocks after: {e}")
        return results

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
        if self.private_key:
            # from_key doesn't need enable_unaudited_hdwallet_features —
            # that flag is only required by from_mnemonic's HD derivation
            return Account.from_key(self.private_key)
        Account.enable_unaudited_hdwallet_features()
        return Account.from_mnemonic(
            self.mnemonic,
            account_path=f"m/44'/60'/0'/0/{self.account_number}")

    @property
    def w3(self) -> Web3:
        w3 = Web3(Web3.HTTPProvider(self.url))
        from web3.middleware import SignAndSendRawMiddlewareBuilder

        w3.middleware_onion.add(
            SignAndSendRawMiddlewareBuilder.build(self.account))
        if self.proof_of_authority is not False or any(
                part in self.url for part in ["polygon"]):
            from web3.middleware import ExtraDataToPOAMiddleware
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
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

    def converter(self, value):
        return value.split("(")[0]


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
        elif inp["type"] == "address":
            val = Web3.to_checksum_address(val)
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
@option(
    "--private-key",
    expose_class=Eth,
    help="Use a private key directly instead of a mnemonic",
    default=None,
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
    help=("The abi to interract with the contract."
          " Accepts a filesystem path or `alias:<name>` to reference"
          " an ABI bundled with this extension (under files/<name>.json)."),
    expose_class=Eth,
    type=AbiPath(),
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
    elif isinstance(data, Decimal):
        return str(data)
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


def resolve_block(spec, default_latest):
    """Turn a --since/--until spec into a block number.

    Accepts a bare block number, the keywords `earliest`/`latest`/`now`, or
    any human date/time (parsed with parsedatetime and located by timestamp)."""
    eth: Eth = config.eth
    if spec is None or spec in ("latest", "now"):
        return eth.w3.eth.block_number if default_latest else 0
    if spec == "earliest":
        return 0
    if spec.isdigit():
        return int(spec)
    moment: datetime = parsedatetime(spec)[0]
    return eth.block_at_timestamp(moment.timestamp())


@contract.command()
@argument("address", help="The wallet whose balance to reconstruct")
@option("--since",
        help="Start of the window: a date/time (e.g. '7 days ago'),"
             " a block number, or 'earliest' (default: 7 days ago)",
        default="7 days ago")
@option("--until",
        help="End of the window: a date/time, a block number, or 'now'"
             " (default: now)",
        default=None)
@flag("--timestamps/--no-timestamps",
      help="Resolve the time of each block (extra RPC calls)",
      default=True)
@option("--plot-output",
        help="Render the balance as a step graph (PNG) to this path",
        default=None)
def balance_history(address, since, until, timestamps, plot_output):
    """Reconstruct the ERC20 balance history of an address from Transfer events.

    Requires an abi exposing the `Transfer` event (and ideally `decimals`),
    e.g. `--abi-path alias:usdc`. Emits one JSON record per transfer touching
    the address over the window, in chronological order, each carrying the
    balance right after that transfer — ready to plot as a step series.

    The balance is reconstructed *backward* from the current on-chain balance
    (`balanceOf(until)`), so it works against non-archival RPCs: no historical
    state read is needed. The first record is a synthetic `baseline` anchoring
    the balance at the start of the window.

    With --plot-output, also draw the balance over time as a step graph."""
    eth: Eth = config.eth
    contract = eth.contract
    # the plot's x-axis needs block times, so force their resolution
    need_times = timestamps or plot_output

    checksummed = Web3.to_checksum_address(address)
    if checksummed != address:
        LOGGER.warning(f"Converting {address} to checksum address {checksummed}")
    address = checksummed

    from_block = resolve_block(since, default_latest=False)
    to_block = resolve_block(until, default_latest=True)

    try:
        decimals = contract.caller.decimals()
    except Exception:
        LOGGER.warning("Could not read decimals(), assuming 18")
        decimals = 18
    scale = Decimal(10)**decimals

    def humanize(value):
        return Decimal(value) / scale

    points = []  # (datetime, balance) collected for the optional plot

    def emit(block, balance, **extra):
        record = {"block": block, **extra, "balance": humanize(balance)}
        if need_times:
            moment = datetime.fromtimestamp(eth.block_timestamp(block))
            if plot_output:
                points.append((moment, humanize(balance)))
            if timestamps:
                record = {"timestamp": moment.isoformat(), **record}
        print(json_dumps(make_serializable(record)))

    logs = eth.transfer_logs(address, from_block, to_block)

    # Walk backward from the current balance, recording the balance *after*
    # each transfer; this avoids any historical-state read.
    running = contract.caller.balanceOf(address, block_identifier=to_block)
    enriched = []
    for log in reversed(logs):
        value = log["value"]
        is_in = log["to"] == address
        is_out = log["from"] == address
        direction = "self" if (is_in and is_out) else "in" if is_in else "out"
        enriched.append((log, direction, value, running))
        if is_in:
            running -= value
        if is_out:
            running += value
    enriched.reverse()
    # `running` is now the balance at the start of the window
    baseline = running

    emit(from_block, baseline, direction="baseline")
    for log, direction, value, balance_after in enriched:
        emit(log["blockNumber"], balance_after,
             tx_hash=log["tx_hash"],
             log_index=log["logIndex"],
             **{"from": log["from"], "to": log["to"]},
             direction=direction,
             amount=humanize(value),
             amount_raw=value)

    if plot_output:
        try:
            symbol = contract.caller.symbol()
        except Exception:
            symbol = "token"
        plot_balance_history(points, plot_output, address, symbol)
        LOGGER.info(f"Wrote balance graph to {plot_output}")


def plot_balance_history(points, output, address, symbol):
    "Draw (datetime, balance) points as a step graph saved to `output`."
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    times = [moment for moment, _ in points]
    balances = [float(balance) for _, balance in points]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.step(times, balances, where="post")
    ax.set_title(f"{symbol} balance of {address}")
    ax.set_ylabel(symbol)
    ax.set_xlabel("time")
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(output, dpi=120)
    plt.close(fig)


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
@argument("address", help="Default to my address", required=False)
@option("--unit",
        help="What unit to show",
        type=click.Choice(units),
        default="wei")
def balance(address, unit):
    "Get the balance of the given address"
    address = address or config.eth.myaddress
    checksummed = Web3.to_checksum_address(address)
    if checksummed != address:
        LOGGER.warning(f"Converting {address} to checksum address {checksummed}")
    value = config.eth.w3.eth.get_balance(checksummed)
    eth: Eth = config.eth
    print(eth.w3.from_wei(value, unit))


@eth.command()
@argument("address")
def history(address):
    checksummed = Web3.to_checksum_address(address)
    if checksummed != address:
        LOGGER.warning(f"Converting {address} to checksum address {checksummed}")
    for history_ in config.eth.history(checksummed):
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
    checksummed = Web3.to_checksum_address(to)
    if checksummed != to:
        LOGGER.warning(f"Converting {to} to checksum address {checksummed}")
    eth: Eth = config.eth
    result = eth.w3.eth.send_transaction({
        "from": eth.myaddress,
        "to": checksummed,
        "value": to_wei(amount, unit)
    })
    click.echo(result.hex())


@eth.command()
@argument("public_key", help="The public key (hex, with or without 0x prefix)")
def public_key_to_address(public_key):
    "Derive an Ethereum address from a public key"
    from eth_utils import keccak
    key_bytes = bytes.fromhex(public_key.removeprefix("0x"))
    # For uncompressed keys (65 bytes starting with 04), skip the 04 prefix
    if len(key_bytes) == 65 and key_bytes[0] == 0x04:
        key_bytes = key_bytes[1:]
    address = Web3.to_checksum_address(keccak(key_bytes)[-20:])
    print(address)


@eth.command()
@argument("address", help="The contract address to check")
def is_smartcontract(address):
    "Check if an address is a smart contract (exit 0 = yes, 1 = no)"
    checksummed = Web3.to_checksum_address(address)
    bytecode = config.eth.w3.eth.get_code(checksummed)
    if bytecode and bytecode != b'':
        LOGGER.info(f"{checksummed}: {len(bytecode)} bytes of bytecode")
    else:
        LOGGER.info(f"{checksummed}: no bytecode")
        ctx = click.get_current_context()
        ctx.exit(1)


@eth.command()
def generate_mnemonic():
    "Generate a private key to play with"
    from mnemonic import Mnemonic
    m = Mnemonic("english")
    words = m.generate()
    print(words)
