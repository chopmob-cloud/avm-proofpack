"""Command-line interface: capture and verify proofpack bundles."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__
from .bundle import Bundle, BundleError, dump_bundle
from .capture import CaptureError, NotYetProvable, capture
from .client import NodeError
from .verify import VerificationError, corroborate, verify_bundle

_POLL_SECONDS = 15.0


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


def _run_corroboration(bundle: Bundle, nodes_argument: str) -> bool:
    urls = [url.strip() for url in nodes_argument.split(",") if url.strip()]
    if not urls:
        print("error: --corroborate given but no node URLs parsed", file=sys.stderr)
        return False
    report = corroborate(bundle, urls)
    for result in report.results:
        line = f"corroborate {result.node}: {result.status}"
        if result.detail:
            line += f" ({result.detail})"
        print(line)
    ok = report.agreeing == len(urls)
    print(f"corroboration: {report.agreeing}/{len(urls)} nodes agree")
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
    report = verify_bundle(bundle)
    _print_report(report)

    if args.corroborate:
        if not _run_corroboration(bundle, args.corroborate):
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


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        bundle = Bundle.load(args.bundle)
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    expected_genesis = None
    if args.genesis_hash is not None:
        import base64

        try:
            expected_genesis = base64.b64decode(args.genesis_hash, validate=True)
        except Exception as exc:
            print(f"error: --genesis-hash is not valid base64: {exc}", file=sys.stderr)
            return 1
        if len(expected_genesis) != 32:
            print(
                f"error: --genesis-hash must decode to 32 bytes, got "
                f"{len(expected_genesis)}",
                file=sys.stderr,
            )
            return 1

    try:
        report = verify_bundle(bundle, expected_genesis_hash=expected_genesis)
    except VerificationError as exc:
        print(f"VERIFICATION FAILED [{exc.check}]: {exc.detail}", file=sys.stderr)
        return 1

    _print_report(report)

    corroborated = False
    if args.corroborate:
        if not _run_corroboration(bundle, args.corroborate):
            return 1
        corroborated = True

    # Offline structure is sound, but the trust root is the bundle's own
    # unauthenticated state proof message. Refuse a bare success unless the
    # trust root was corroborated against independent nodes, or the operator
    # explicitly accepts unattested evidence.
    if corroborated:
        print("verification: OK (structure verified; trust root corroborated)")
        return 0
    if args.accept_unattested:
        print(
            "verification: OK (structure only; trust root UNATTESTED, "
            "accepted by --accept-unattested)"
        )
        return 0
    print(
        "verification: STRUCTURE OK, but the trust root is NOT attested. "
        "Re-run with --corroborate <node,node> to compare the state proof "
        "message against independent nodes, or --accept-unattested to accept "
        "structure-only.",
        file=sys.stderr,
    )
    return 2


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
        "state proof message",
    )
    capture_parser.set_defaults(func=_cmd_capture)

    verify_parser = subparsers.add_parser(
        "verify", help="verify a previously captured bundle offline"
    )
    verify_parser.add_argument("bundle", help="path to the bundle JSON file")
    verify_parser.add_argument(
        "--genesis-hash",
        help="base64 genesis hash the bundle must belong to (chain pinning)",
    )
    verify_parser.add_argument(
        "--corroborate",
        help="comma-separated node URLs that must agree on the state proof "
        "message; this is what raises the trust root above 'unattested'",
    )
    verify_parser.add_argument(
        "--accept-unattested",
        action="store_true",
        help="succeed on structure-only verification without corroborating "
        "the trust root (use only when you already trust the bundle's source)",
    )
    verify_parser.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
