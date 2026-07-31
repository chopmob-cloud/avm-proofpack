"""Command-line interface: capture, verify and extract proofpack bundles."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time

from . import __version__
from .bundle import Bundle, BundleError, dump_bundle
from .capture import CaptureError, NotYetProvable, capture
from .chains import CHAINS, Chain, get_chain
from .client import NodeError
from .extract import ExtractionError, extract_payment
from .verify import VerificationError, corroborate, verify_bundle

_POLL_SECONDS = 15.0

#: Sentinel value for --corroborate meaning "the chain's default node list".
_CORROBORATE_DEFAULT = "default"


def _print_report(report) -> None:
    print(f"txid:                     {report.txid}")
    print(f"round:                    {report.round}")
    print(f"chain:                    {report.genesis_id}")
    print(f"genesis hash:             {report.genesis_hash_b64}")
    print(f"block hash:               {report.block_hash_b64}")
    print(f"attested interval:        [{report.first_attested_round}, "
          f"{report.last_attested_round}]")
    print(f"block headers commitment: {report.block_headers_commitment_b64}")
    print(f"checks passed:            {', '.join(report.checks)}")
    print(f"trust root:               {report.trust_root}")


def _resolve_chain(args: argparse.Namespace) -> Chain | None:
    """The pinned chain, if --chain was given (argparse validated the name)."""
    if getattr(args, "chain", None) is None:
        return None
    return get_chain(args.chain)


def _corroboration_urls(
    nodes_argument: str, chain: Chain | None
) -> list[str] | None:
    """Parse --corroborate, expanding the 'default' sentinel via --chain.

    Returns ``None`` (with a printed error) when the argument cannot be
    resolved: 'default' without --chain, or no URLs at all.
    """
    if nodes_argument == _CORROBORATE_DEFAULT:
        if chain is None:
            print(
                "error: --corroborate default requires --chain to select "
                "whose default node list to use",
                file=sys.stderr,
            )
            return None
        return list(chain.default_corroboration_nodes)
    urls = [url.strip() for url in nodes_argument.split(",") if url.strip()]
    if not urls:
        print("error: --corroborate given but no node URLs parsed", file=sys.stderr)
        return None
    return urls


def _run_corroboration(
    bundle: Bundle, nodes_argument: str, chain: Chain | None = None, *, stream=None
) -> bool:
    stream = stream if stream is not None else sys.stdout
    urls = _corroboration_urls(nodes_argument, chain)
    if urls is None:
        return False
    report = corroborate(bundle, urls)
    for result in report.results:
        line = f"corroborate {result.node}: {result.status}"
        if result.detail:
            line += f" ({result.detail})"
        print(line, file=stream)
    ok = report.agreeing == len(urls)
    print(f"corroboration: {report.agreeing}/{len(urls)} nodes agree", file=stream)
    return ok


def _cmd_capture(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.wait
    while True:
        try:
            bundle_dict = capture(args.node, args.txid, args.round)
            break
        except NotYetProvable as exc:
            if time.monotonic() >= deadline:
                print(f"error: {exc}", file=sys.stderr)
                if args.wait == 0:
                    print(
                        "hint: the state proof interval (256 rounds) may not "
                        "have closed; retry with --wait 1200",
                        file=sys.stderr,
                    )
                return 1
            print("state proof not yet available; waiting...", file=sys.stderr)
            time.sleep(_POLL_SECONDS)
        except (CaptureError, NodeError, BundleError, VerificationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if not args.node.lower().startswith("https://"):
        print(
            f"warning: capturing over a non-HTTPS node ({args.node}); an "
            "on-path attacker can substitute block data. Prefer https and "
            "--corroborate.",
            file=sys.stderr,
        )

    bundle = Bundle.from_dict(bundle_dict)
    chain = _resolve_chain(args)
    if chain is not None and bundle.genesis_hash != chain.genesis_hash:
        # The node served a block from a different chain than the operator
        # expected; refuse to bless (or write) the evidence.
        print(
            f"error: captured bundle's genesis hash "
            f"({base64.b64encode(bundle.genesis_hash).decode('ascii')}) does "
            f"not match --chain {chain.name} ({chain.genesis_hash_b64}); the "
            "node is serving a different chain",
            file=sys.stderr,
        )
        return 1
    report = verify_bundle(bundle)
    _print_report(report)

    if args.corroborate:
        if not _run_corroboration(bundle, args.corroborate, chain):
            return 1
    else:
        # A single-source capture inherits full trust in that one node; the
        # integrity gates catch corruption and codec drift, not a dishonest
        # node serving an internally consistent fabricated block.
        print(
            "note: captured from a single node without corroboration. The "
            "evidence is only as trustworthy as that node until verified with "
            "--corroborate against independent nodes.",
            file=sys.stderr,
        )

    if args.output:
        dump_bundle(bundle_dict, args.output)
        print(f"bundle written: {args.output}")
    return 0


def _expected_genesis_hash(
    args: argparse.Namespace, chain: Chain | None
) -> bytes | None:
    """Resolve chain pinning from --chain or --genesis-hash (exclusive)."""
    if chain is not None:
        return chain.genesis_hash
    if args.genesis_hash is None:
        return None
    try:
        expected = base64.b64decode(args.genesis_hash, validate=True)
    except Exception as exc:
        raise ValueError(f"--genesis-hash is not valid base64: {exc}") from exc
    if len(expected) != 32:
        raise ValueError(
            f"--genesis-hash must decode to 32 bytes, got {len(expected)}"
        )
    return expected


def _gated_verify(
    args: argparse.Namespace, *, status_stream, print_report: bool = False
) -> tuple[int, Bundle, "object"]:
    """Shared verify-then-gate flow for the verify and extract commands.

    Returns ``(exit_code, bundle, report)``; a non-zero exit code means the
    caller must stop (the failure or gating message was already printed).
    Status and corroboration output goes to ``status_stream`` so `extract`
    can keep stdout as pure JSON.
    """
    try:
        bundle = Bundle.load(args.bundle)
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1, None, None  # type: ignore[return-value]

    chain = _resolve_chain(args)
    try:
        expected_genesis = _expected_genesis_hash(args, chain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1, None, None  # type: ignore[return-value]

    try:
        report = verify_bundle(bundle, expected_genesis_hash=expected_genesis)
    except VerificationError as exc:
        print(f"VERIFICATION FAILED [{exc.check}]: {exc.detail}", file=sys.stderr)
        return 1, None, None  # type: ignore[return-value]

    if print_report:
        _print_report(report)

    corroborated = False
    if args.corroborate:
        if not _run_corroboration(
            bundle, args.corroborate, chain, stream=status_stream
        ):
            return 1, None, None  # type: ignore[return-value]
        corroborated = True

    # Offline structure is sound, but the trust root is the bundle's own
    # unauthenticated state proof message. Refuse a bare success unless the
    # trust root was corroborated against independent nodes, or the operator
    # explicitly accepts unattested evidence.
    if corroborated:
        print(
            "verification: OK (structure verified; trust root corroborated)",
            file=status_stream,
        )
        return 0, bundle, report
    if args.accept_unattested:
        print(
            "verification: OK (structure only; trust root UNATTESTED, "
            "accepted by --accept-unattested)",
            file=status_stream,
        )
        return 0, bundle, report
    print(
        "verification: STRUCTURE OK, but the trust root is NOT attested. "
        "Re-run with --corroborate <node,node> to compare the state proof "
        "message against independent nodes, or --accept-unattested to accept "
        "structure-only.",
        file=sys.stderr,
    )
    return 2, None, None  # type: ignore[return-value]


def _cmd_verify(args: argparse.Namespace) -> int:
    code, _bundle, _report = _gated_verify(
        args, status_stream=sys.stdout, print_report=True
    )
    return code


def _cmd_extract(args: argparse.Namespace) -> int:
    """Verify (same trust-root gating as `verify`), then print PaymentFacts.

    All human-facing status goes to stderr; stdout carries exactly one JSON
    object on success, so the command composes into pipelines.
    """
    code, bundle, report = _gated_verify(args, status_stream=sys.stderr)
    if code != 0:
        return code
    try:
        facts = extract_payment(bundle, report=report)
    except (ExtractionError, VerificationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(facts.as_dict(), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        prog="avm-proofpack",
        description=(
            "Capture and verify portable settlement evidence for Algorand "
            "and Voi, anchored in state proofs."
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser(
        "capture", help="capture a bundle for a confirmed transaction"
    )
    capture_parser.add_argument("--node", required=True, help="algod base URL")
    capture_parser.add_argument("--txid", required=True, help="transaction id (base32)")
    capture_parser.add_argument(
        "--round", required=True, type=int, help="confirmed round of the transaction"
    )
    capture_parser.add_argument("-o", "--output", help="write the bundle to this file")
    capture_parser.add_argument(
        "--wait",
        type=float,
        default=0.0,
        help="seconds to wait for the state proof interval to close (default 0)",
    )
    capture_parser.add_argument(
        "--corroborate",
        help="comma-separated additional node URLs that must agree on the "
        "state proof message; 'default' uses the --chain default node list",
    )
    capture_parser.add_argument(
        "--chain",
        choices=sorted(CHAINS),
        help="named chain the captured bundle must belong to; capture fails "
        "if the node serves a different genesis hash",
    )
    capture_parser.set_defaults(func=_cmd_capture)

    def _add_offline_args(sub: argparse.ArgumentParser) -> None:
        """Arguments shared by verify and extract (same trust-root gating)."""
        sub.add_argument("bundle", help="path to the bundle JSON file")
        pin = sub.add_mutually_exclusive_group()
        pin.add_argument(
            "--genesis-hash",
            help="base64 genesis hash the bundle must belong to (chain pinning)",
        )
        pin.add_argument(
            "--chain",
            choices=sorted(CHAINS),
            help="named chain the bundle must belong to (chain pinning by "
            "registry name; mutually exclusive with --genesis-hash)",
        )
        sub.add_argument(
            "--corroborate",
            help="comma-separated node URLs that must agree on the state proof "
            "message; this is what raises the trust root above 'unattested'. "
            "'default' uses the --chain default node list",
        )
        sub.add_argument(
            "--accept-unattested",
            action="store_true",
            help="succeed on structure-only verification without corroborating "
            "the trust root (use only when you already trust the bundle's source)",
        )

    verify_parser = subparsers.add_parser(
        "verify", help="verify a previously captured bundle offline"
    )
    _add_offline_args(verify_parser)
    verify_parser.set_defaults(func=_cmd_verify)

    extract_parser = subparsers.add_parser(
        "extract",
        help="verify a bundle (same gating as verify), then print the "
        "top-level transaction's payment facts as JSON",
    )
    _add_offline_args(extract_parser)
    extract_parser.set_defaults(func=_cmd_extract)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
