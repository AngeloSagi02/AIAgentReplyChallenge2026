"""
main.py - Entry point for Deus Ex LLM fraud agent.

Usage examples:
  python main.py --dataset "../Deus Ex - train" --model mid
  python main.py --dataset "../Deus Ex - train" --model heavy -o output_deus.txt
  python main.py --dataset "../Deus Ex - train" --model google/gemini-2.0-flash-001 --quiet
"""

# pyright: reportMissingImports=false

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent


def _bootstrap_repo_venv_site_packages() -> None:
    """Add repo .venv site-packages to sys.path when not already in a venv."""
    if os.getenv("VIRTUAL_ENV"):
        return

    search_roots = [CURRENT_DIR] + list(CURRENT_DIR.parents)
    for root in search_roots:
        lib_dir = root / ".venv" / "lib"
        if not lib_dir.exists():
            continue

        for site_pkg in sorted(lib_dir.glob("python*/site-packages"), reverse=True):
            site_pkg_str = str(site_pkg)
            if site_pkg_str not in sys.path:
                sys.path.insert(0, site_pkg_str)
            return


_bootstrap_repo_venv_site_packages()

from dotenv import find_dotenv, load_dotenv


if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from agent import (
    MODELS,
    create_fraud_agent,
    flush_langfuse,
    generate_session_id,
    resolve_model_id,
    run_agent,
)
from tools import calibrate_flagged_transactions, get_fallback_transaction_ids, load_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reply Mirror Deus Ex Fraud Detection Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Model presets:
  cheap      = {MODELS['cheap']}  (fast and low-cost)
  mid        = {MODELS['mid']}  (balanced default)
  heavy      = {MODELS['heavy']}  (higher quality)
  gemini-pro = {MODELS['gemini-pro']}  (strong reasoning)

Example:
  python main.py --dataset "../Deus Ex - train" --model mid
""",
    )

    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to dataset folder containing transactions.csv, users.json, locations.json.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="mid",
        help=f"Model preset ({', '.join(MODELS.keys())}) or full OpenRouter model ID.",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.1,
        help="Generation temperature (default: 0.1).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output txt file path (default: ./output_<dataset_name>.txt).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress streaming agent logs.",
    )

    return parser.parse_args()


def validate_env() -> None:
    required = [
        "OPENROUTER_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "LANGFUSE_HOST",
        "TEAM_NAME",
    ]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        print(f"ERROR: Missing environment variables: {', '.join(missing)}")
        print("Fix: define them in the repository root .env file.")
        sys.exit(1)


def ensure_dataset(dataset_path: Path) -> None:
    if not dataset_path.exists():
        print(f"ERROR: Dataset path not found: {dataset_path}")
        sys.exit(1)

    required_files = ["transactions.csv", "users.json", "locations.json"]
    missing = [name for name in required_files if not (dataset_path / name).exists()]
    if missing:
        print(f"ERROR: Missing required files in dataset: {', '.join(missing)}")
        sys.exit(1)


def make_default_output_path(dataset_name: str) -> Path:
    safe = dataset_name.lower().replace(" ", "_").replace("-", "_")
    return Path(f"output_{safe}.txt")


def normalize_final_ids(flagged_ids: list[str], total_transactions: int) -> list[str]:
    unique_ordered: list[str] = []
    seen: set[str] = set()
    for tid in flagged_ids:
        clean = tid.strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique_ordered.append(clean)

    if not unique_ordered:
        fallback = get_fallback_transaction_ids(max_ratio=0.10, min_count=14)
        return sorted(set(fallback))

    calibrated = calibrate_flagged_transactions(
        unique_ordered,
        min_ratio=0.022,
        target_ratio=0.05,
        max_ratio=0.20,
        min_count=40,
    )

    if not calibrated:
        fallback = get_fallback_transaction_ids(max_ratio=0.10, min_count=14)
        return sorted(set(fallback))

    if len(calibrated) >= total_transactions:
        fallback = get_fallback_transaction_ids(max_ratio=0.12, min_count=18)
        return sorted(set(fallback))

    # Keep false positives constrained when an extreme over-flag occurs.
    max_allowed = max(1, int(total_transactions * 0.45))
    if len(calibrated) > max_allowed:
        fallback = get_fallback_transaction_ids(max_ratio=0.18, min_count=22)
        return sorted(set(fallback))

    return calibrated


def write_ascii_output(output_path: Path, transaction_ids: list[str]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(f"{tid}\n" for tid in transaction_ids)
    output_path.write_bytes(payload.encode("ascii", errors="strict"))


def main() -> None:
    load_dotenv(find_dotenv())
    args = parse_args()

    validate_env()

    dataset_path = Path(args.dataset)
    ensure_dataset(dataset_path)

    model_id = resolve_model_id(args.model)
    session_id = generate_session_id()
    dataset_name = dataset_path.name

    output_path = Path(args.output) if args.output else make_default_output_path(dataset_name)

    print("=" * 72)
    print("  Reply Mirror - Deus Ex Fraud Detection Agent")
    print("=" * 72)
    print(f"  Dataset:    {dataset_name}")
    print(f"  Path:       {dataset_path.resolve()}")
    print(f"  Model:      {model_id}")
    print(f"  Temp:       {args.temperature}")
    print(f"  Output:     {output_path}")
    print(f"  Session ID: {session_id}")
    print("=" * 72)

    print("\nLoading dataset and building indexes...")
    meta = load_dataset(dataset_path)
    print(f"  Citizens:             {meta['citizens']}")
    print(f"  Transactions:         {meta['transactions']}")
    print(f"  Location pings:       {meta['location_pings']}")
    print(f"  SMS records:          {meta['sms']}")
    print(f"  Mail records:         {meta['mails']}")
    print(f"  High-risk candidates: {meta['high_risk_candidates']}")

    agent = create_fraud_agent(model_id=model_id, temperature=args.temperature)

    flagged_ids: list[str] = []
    try:
        flagged_ids = run_agent(
            agent,
            session_id=session_id,
            dataset_name=dataset_name,
            verbose=not args.quiet,
        )
    finally:
        flush_langfuse()

    final_ids = normalize_final_ids(flagged_ids, total_transactions=meta["transactions"])

    write_ascii_output(output_path, final_ids)

    if not final_ids:
        print("WARNING: Output is empty. This is invalid for challenge submission.")
    if len(final_ids) == meta["transactions"]:
        print("WARNING: All transactions were flagged. This is invalid for challenge submission.")

    print("\n" + "=" * 72)
    print("  RESULTS")
    print("=" * 72)
    print(f"  Flagged transactions: {len(final_ids)} / {meta['transactions']}")
    print(f"  Output file:          {output_path.resolve()}")
    print(f"  Session ID:           {session_id}")
    print("=" * 72)


if __name__ == "__main__":
    main()
