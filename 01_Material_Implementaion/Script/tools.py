"""
tools.py - Data ingestion and investigation tools for Deus Ex fraud detection.

Design principles:
  - Deterministic scoring is used for triage and cost control.
  - The LLM remains the final decision-maker through tool-driven reasoning.
  - Expensive evidence (SMS/email content) is loaded and queried selectively.
"""

from __future__ import annotations

import csv
import json
import math
import re
import statistics
import unicodedata
from collections import defaultdict, deque
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import tool


# ---------------------------------------------------------------------------
# Global data store (populated by load_dataset)
# ---------------------------------------------------------------------------

_DATA: dict[str, Any] = {}


SUSPICIOUS_DESC_KEYWORDS = (
    "urgent",
    "verify",
    "verification",
    "security",
    "winner",
    "claim",
    "prize",
    "release fee",
    "admin fee",
    "crypto",
    "bitcoin",
    "wallet",
    "gift card",
    "overdue",
    "approve payment",
    "password",
)

SUSPICIOUS_TEXT_KEYWORDS = (
    "urgent",
    "verify",
    "verification",
    "frozen",
    "suspended",
    "confirm",
    "claim",
    "winner",
    "prize",
    "fee",
    "security",
    "crypto",
    "wallet",
    "customs",
    "release",
    "password",
    "approve",
    "pay now",
    "within 24",
    "within 48",
)

BRAND_KEYWORDS = (
    "paypal",
    "paypa1",
    "amazon",
    "amaz0n",
    "coinbase",
    "dhl",
    "fedex",
    "chase",
    "hsbc",
    "visa",
)

URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
COMM_TS_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\b")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _parse_comm_ts(text: str) -> datetime | None:
    """Parse a communication timestamp from SMS/mail raw payload."""
    if not text:
        return None

    match = COMM_TS_RE.search(text)
    if match:
        ts = _parse_ts(f"{match.group(1)}T{match.group(2)}")
        if ts is not None:
            return ts

    for line in text.splitlines():
        if not line.lower().startswith("date:"):
            continue
        raw = line.split(":", 1)[1].strip()
        try:
            parsed = parsedate_to_datetime(raw)
            if parsed is not None:
                # Keep a naive datetime to compare with transaction timestamps.
                return parsed.replace(tzinfo=None)
        except (TypeError, ValueError):
            continue

    return None


def _normalize_text(value: str) -> str:
    if not value:
        return ""
    decomposed = unicodedata.normalize("NFKD", value)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    lowered = stripped.lower()
    return re.sub(r"\s+", " ", lowered).strip()


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]

    ordered = sorted(values)
    position = (len(ordered) - 1) * max(0.0, min(1.0, q))
    left = int(math.floor(position))
    right = int(math.ceil(position))
    if left == right:
        return ordered[left]
    weight = position - left
    return ordered[left] * (1.0 - weight) + ordered[right] * weight


def _median_abs_deviation(values: list[float]) -> float:
    if not values:
        return 0.0
    median = statistics.median(values)
    deviations = [abs(v - median) for v in values]
    return statistics.median(deviations)


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return URL_RE.findall(text)


def _extract_domains(text: str) -> list[str]:
    domains: list[str] = []
    for url in _extract_urls(text):
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
        if host:
            domains.append(host)
    return domains


def _looks_like_suspicious_domain(host: str) -> bool:
    host_norm = host.lower()
    if any(k in host_norm for k in ("secure", "verify", "claim", "billing", "release", "update")):
        if any(brand in host_norm for brand in BRAND_KEYWORDS):
            return True
        if re.search(r"\d", host_norm):
            return True

    if any(brand in host_norm for brand in ("paypa1", "amaz0n", "coinbase-secure", "dhl-release")):
        return True

    return False


def _score_text_for_phishing(text: str) -> dict[str, Any]:
    norm = _normalize_text(text)
    keyword_hits = [k for k in SUSPICIOUS_TEXT_KEYWORDS if k in norm]
    domains = _extract_domains(text)
    suspicious_domains = [d for d in domains if _looks_like_suspicious_domain(d)]

    score = 0.0
    score += min(2.5, 0.4 * len(keyword_hits))
    score += min(2.5, 0.8 * len(suspicious_domains))

    if "http://" in text.lower():
        score += 0.4

    return {
        "score": round(score, 3),
        "keyword_hits": keyword_hits,
        "domains": domains,
        "suspicious_domains": suspicious_domains,
    }


def _build_name_index(citizen_to_user: dict[str, dict[str, Any]]) -> dict[str, set[str]]:
    name_index: dict[str, set[str]] = defaultdict(set)

    for citizen_id, user in citizen_to_user.items():
        first = _normalize_text(str(user.get("first_name", "")))
        last = _normalize_text(str(user.get("last_name", "")))
        full = " ".join(part for part in (first, last) if part)

        if full:
            name_index[full].add(citizen_id)
        if first and len(first) >= 3:
            name_index[first].add(citizen_id)
        if last and len(last) >= 4:
            name_index[last].add(citizen_id)

    return dict(name_index)


def _match_citizens_in_text(text: str, name_index: dict[str, set[str]]) -> set[str]:
    norm_text = f" {_normalize_text(text)} "
    matches: set[str] = set()

    # Match longer names first to reduce false-positive first-name matches.
    for name in sorted(name_index.keys(), key=len, reverse=True):
        token = f" {name} "
        if token in norm_text:
            matches.update(name_index[name])

    return matches


def _strip_html(text: str) -> str:
    no_tags = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", no_tags).strip()


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ---------------------------------------------------------------------------
# Dataset loading and indexing
# ---------------------------------------------------------------------------


def load_dataset(dataset_dir: str | Path) -> dict[str, Any]:
    """Load Deus Ex files and build indexes/risk priors for tool usage."""
    d = Path(dataset_dir)

    tx_path = d / "transactions.csv"
    users_path = d / "users.json"
    locations_path = d / "locations.json"
    sms_path = d / "sms.json"
    mails_path = d / "mails.json"

    if not tx_path.exists():
        raise FileNotFoundError(f"transactions.csv not found in {d}")
    if not users_path.exists():
        raise FileNotFoundError(f"users.json not found in {d}")
    if not locations_path.exists():
        raise FileNotFoundError(f"locations.json not found in {d}")

    transactions: list[dict[str, Any]] = []
    with tx_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            transactions.append(row)

    users: list[dict[str, Any]] = json.loads(users_path.read_text(encoding="utf-8"))
    locations: list[dict[str, Any]] = json.loads(locations_path.read_text(encoding="utf-8"))
    sms_rows: list[dict[str, Any]] = json.loads(sms_path.read_text(encoding="utf-8")) if sms_path.exists() else []
    mail_rows: list[dict[str, Any]] = json.loads(mails_path.read_text(encoding="utf-8")) if mails_path.exists() else []

    iban_to_user: dict[str, dict[str, Any]] = {str(u.get("iban", "")).strip(): u for u in users if u.get("iban")}

    # Unicode-safe citizen discovery by IBAN matching (no ASCII-only regex assumptions).
    citizen_to_user: dict[str, dict[str, Any]] = {}
    citizen_to_iban: dict[str, str] = {}

    for t in transactions:
        sender_id = str(t.get("sender_id", "")).strip()
        sender_iban = str(t.get("sender_iban", "")).strip()
        if sender_id and sender_iban and sender_iban in iban_to_user:
            citizen_to_user.setdefault(sender_id, iban_to_user[sender_iban])
            citizen_to_iban.setdefault(sender_id, sender_iban)

        recipient_id = str(t.get("recipient_id", "")).strip()
        recipient_iban = str(t.get("recipient_iban", "")).strip()
        if recipient_id and recipient_iban and recipient_iban in iban_to_user:
            citizen_to_user.setdefault(recipient_id, iban_to_user[recipient_iban])
            citizen_to_iban.setdefault(recipient_id, recipient_iban)

    txns_by_sender: dict[str, list[dict[str, Any]]] = defaultdict(list)
    txns_by_recipient: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for t in transactions:
        sender_id = str(t.get("sender_id", "")).strip()
        recipient_id = str(t.get("recipient_id", "")).strip()

        if sender_id:
            txns_by_sender[sender_id].append(t)
        if recipient_id:
            txns_by_recipient[recipient_id].append(t)

    locs_by_citizen: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in locations:
        cid = str(row.get("biotag", "")).strip()
        if cid:
            locs_by_citizen[cid].append(row)

    # Ensure deterministic ordering for temporal analysis.
    for cid, rows in txns_by_sender.items():
        rows.sort(key=lambda r: str(r.get("timestamp", "")))
    for cid, rows in txns_by_recipient.items():
        rows.sort(key=lambda r: str(r.get("timestamp", "")))
    for cid, rows in locs_by_citizen.items():
        rows.sort(key=lambda r: str(r.get("timestamp", "")))

    name_index = _build_name_index(citizen_to_user)

    sms_by_citizen: dict[str, list[str]] = defaultdict(list)
    mails_by_citizen: dict[str, list[str]] = defaultdict(list)
    phishing_events_by_citizen: dict[str, list[datetime]] = defaultdict(list)
    comm_summary: dict[str, dict[str, Any]] = {
        cid: {
            "risk_score": 0.0,
            "sms_count": 0,
            "mail_count": 0,
            "suspicious_sms": 0,
            "suspicious_mails": 0,
            "top_alerts": [],
            "domains": set(),
        }
        for cid in citizen_to_user.keys()
    }

    for row in sms_rows:
        text = str(row.get("sms", ""))
        if not text:
            continue

        matched = _match_citizens_in_text(text, name_index)
        if not matched:
            continue

        score_info = _score_text_for_phishing(text)
        comm_ts = _parse_comm_ts(text)
        for cid in matched:
            sms_by_citizen[cid].append(text)
            summary = comm_summary[cid]
            summary["sms_count"] += 1
            summary["risk_score"] += score_info["score"] * 0.9
            summary["domains"].update(score_info["domains"])
            if score_info["score"] >= 1.4:
                summary["suspicious_sms"] += 1
                if comm_ts is not None:
                    phishing_events_by_citizen[cid].append(comm_ts)
                summary["top_alerts"].append(
                    {
                        "channel": "sms",
                        "score": score_info["score"],
                        "keywords": score_info["keyword_hits"][:4],
                        "domains": score_info["suspicious_domains"][:3],
                        "preview": text[:220],
                    }
                )

    for row in mail_rows:
        text = str(row.get("mail", ""))
        if not text:
            continue

        matched = _match_citizens_in_text(text, name_index)
        if not matched:
            continue

        score_info = _score_text_for_phishing(text)
        clean_text = _strip_html(text)
        comm_ts = _parse_comm_ts(text)

        for cid in matched:
            mails_by_citizen[cid].append(text)
            summary = comm_summary[cid]
            summary["mail_count"] += 1
            summary["risk_score"] += score_info["score"]
            summary["domains"].update(score_info["domains"])
            if score_info["score"] >= 1.6:
                summary["suspicious_mails"] += 1
                if comm_ts is not None:
                    phishing_events_by_citizen[cid].append(comm_ts)
                summary["top_alerts"].append(
                    {
                        "channel": "mail",
                        "score": score_info["score"],
                        "keywords": score_info["keyword_hits"][:5],
                        "domains": score_info["suspicious_domains"][:4],
                        "preview": clean_text[:260],
                    }
                )

    for cid, summary in comm_summary.items():
        summary["risk_score"] = round(summary["risk_score"], 3)
        summary["domains"] = sorted(summary["domains"])[:40]
        summary["top_alerts"] = sorted(
            summary["top_alerts"],
            key=lambda item: float(item.get("score", 0.0)),
            reverse=True,
        )[:14]

    for cid, event_list in phishing_events_by_citizen.items():
        event_list.sort()

    # Build cross-citizen risk profile for counterparties to capture coordinated fraud endpoints.
    recipient_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "senders": set(),
            "amounts": [],
            "night": 0,
            "type_counts": defaultdict(int),
        }
    )
    for tx in transactions:
        sender = str(tx.get("sender_id", "")).strip()
        if sender not in citizen_to_user:
            continue

        recipient_key = (
            str(tx.get("recipient_id", "")).strip()
            or str(tx.get("recipient_iban", "")).strip()
            or "UNKNOWN"
        )
        stat = recipient_stats[recipient_key]
        stat["count"] += 1
        stat["senders"].add(sender)
        amount = _safe_float(tx.get("amount", 0.0), default=0.0)
        stat["amounts"].append(amount)
        tx_type = str(tx.get("transaction_type", "unknown")).strip() or "unknown"
        stat["type_counts"][tx_type] += 1
        ts = _parse_ts(str(tx.get("timestamp", "")))
        if ts is not None and 0 <= ts.hour < 6:
            stat["night"] += 1

    recipient_risk_by_counterparty: dict[str, float] = {}
    for recipient_key, stat in recipient_stats.items():
        count = int(stat["count"])
        if count <= 0:
            continue

        unique_senders = len(stat["senders"])
        unique_sender_ratio = unique_senders / count
        amounts = [float(v) for v in stat["amounts"] if float(v) >= 0.0]
        mean_amount = statistics.mean(amounts) if amounts else 0.0
        q90_amount = _quantile(amounts, 0.90) if amounts else 0.0
        night_ratio = stat["night"] / count
        type_counts = stat["type_counts"]
        transfer_ecom_ratio = (
            (type_counts.get("transfer", 0) + type_counts.get("e-commerce", 0)) / count
        )

        recipient_risk = 0.0
        if count >= 4 and unique_sender_ratio >= 0.75 and q90_amount >= 220.0:
            recipient_risk += 1.2
        if count >= 5 and transfer_ecom_ratio >= 0.85 and mean_amount >= 160.0:
            recipient_risk += 0.9
        if count >= 6 and night_ratio >= 0.30:
            recipient_risk += 0.8
        if unique_senders >= 5 and (count / max(1, unique_senders)) <= 1.7:
            recipient_risk += 0.8

        if recipient_risk > 0.0:
            recipient_risk_by_counterparty[recipient_key] = round(recipient_risk, 3)

    risk_by_txn: dict[str, dict[str, Any]] = {}
    citizen_overview: dict[str, dict[str, Any]] = {}

    all_scores: list[float] = []

    for cid in sorted(citizen_to_user.keys()):
        outgoing = txns_by_sender.get(cid, [])
        incoming = txns_by_recipient.get(cid, [])

        user = citizen_to_user.get(cid, {})
        salary = _safe_float(user.get("salary", 0.0), default=0.0)
        monthly_salary = salary / 12.0 if salary > 0 else 0.0

        amounts = [_safe_float(t.get("amount", 0.0), default=0.0) for t in outgoing]
        median_amount = statistics.median(amounts) if amounts else 0.0
        q90_amount = _quantile(amounts, 0.90)
        mad_amount = _median_abs_deviation(amounts)

        known_cities = {
            _normalize_text(str(loc.get("city", "")))
            for loc in locs_by_citizen.get(cid, [])
            if loc.get("city")
        }

        home_city = _normalize_text(str(user.get("residence", {}).get("city", "")))
        if home_city:
            known_cities.add(home_city)

        type_counts: dict[str, int] = defaultdict(int)
        method_counts: dict[str, int] = defaultdict(int)
        night_count = 0

        counterparty_seen: dict[str, int] = defaultdict(int)
        recent_window: deque[tuple[datetime, float]] = deque()
        counterparty_recent_window: dict[str, deque[tuple[datetime, float]]] = defaultdict(deque)

        previous_time: datetime | None = None
        previous_balance: float | None = None

        comm_risk = float(comm_summary.get(cid, {}).get("risk_score", 0.0))
        phishing_events = phishing_events_by_citizen.get(cid, [])

        for tx in outgoing:
            tid = str(tx.get("transaction_id", "")).strip()
            if not tid:
                continue

            score = 0.0
            reasons: list[str] = []
            mitigation_signals: list[str] = []

            amount = _safe_float(tx.get("amount", 0.0), default=0.0)
            tx_type = str(tx.get("transaction_type", "unknown")).strip() or "unknown"
            payment_method = str(tx.get("payment_method", "")).strip()
            timestamp = _parse_ts(str(tx.get("timestamp", "")))
            hour = timestamp.hour if timestamp else -1

            type_counts[tx_type] += 1
            if payment_method:
                method_counts[payment_method] += 1

            if 0 <= hour < 6:
                night_count += 1
                score += 0.85
                reasons.append("executed during night hours (00:00-06:00)")

            if monthly_salary > 0:
                salary_ratio = amount / max(1.0, monthly_salary)
                if salary_ratio >= 1.5:
                    score += 2.4
                    reasons.append("amount exceeds 150% of monthly salary")
                elif salary_ratio >= 1.0:
                    score += 1.5
                    reasons.append("amount exceeds monthly salary")
                elif salary_ratio >= 0.7:
                    score += 0.8
                    reasons.append("amount is high versus monthly salary")

            if (
                median_amount > 0
                and amount > max(median_amount * 3.0, monthly_salary * 0.08, 90.0)
            ):
                score += 1.2
                reasons.append("3x above median spend")

            if (
                q90_amount > 0
                and amount > max(q90_amount * 1.4, monthly_salary * 0.07, 80.0)
            ):
                score += 0.9
                reasons.append("well above personal 90th percentile")

            if mad_amount > 0:
                robust_z = abs(amount - median_amount) / max(0.001, 1.4826 * mad_amount)
                if robust_z > 5.0 and amount > max(monthly_salary * 0.08, 95.0):
                    score += 1.0
                    reasons.append("strong amount outlier versus personal history")

            if tx_type in {"withdrawal", "transfer"} and amount > max(250.0, monthly_salary * 0.25):
                score += 0.4
                reasons.append(f"high-value {tx_type}")

            location = str(tx.get("location", "")).strip()
            location_norm = _normalize_text(location)
            if tx_type == "in-person payment" and location and known_cities and location_norm not in known_cities:
                score += 1.2
                reasons.append("in-person location not seen in mobility history")

            counterparty = (
                str(tx.get("recipient_id", "")).strip()
                or str(tx.get("recipient_iban", "")).strip()
                or "UNKNOWN"
            )
            is_new_counterparty = counterparty_seen[counterparty] == 0
            if is_new_counterparty and amount > max(120.0, monthly_salary * 0.25):
                score += 1.1
                reasons.append("first payment to this counterparty with significant amount")

            if timestamp:
                while recent_window and (timestamp - recent_window[0][0]).total_seconds() > 3600:
                    recent_window.popleft()

                recent_window.append((timestamp, amount))
                burst_total = sum(v for _, v in recent_window)

                if len(recent_window) >= 3 and burst_total > max(400.0, monthly_salary * 0.8):
                    score += 1.0
                    reasons.append("high spending burst within one hour")

                if previous_time is not None:
                    delta_minutes = (timestamp - previous_time).total_seconds() / 60.0
                    if 0.0 <= delta_minutes <= 20.0 and amount > max(80.0, monthly_salary * 0.2):
                        score += 0.8
                        reasons.append("rapid follow-up high-value transaction")

                cp_window = counterparty_recent_window[counterparty]
                while cp_window and (timestamp - cp_window[0][0]).total_seconds() > 48 * 3600:
                    cp_window.popleft()
                cp_window.append((timestamp, amount))

                cp_window_total = sum(v for _, v in cp_window)
                if len(cp_window) >= 2 and cp_window_total >= max(260.0, monthly_salary * 0.45):
                    score += 0.9
                    reasons.append("repeated payments to same counterparty within 48h")

                if (
                    counterparty_seen[counterparty] <= 1
                    and len(cp_window) >= 2
                    and comm_risk >= 4.0
                    and amount > max(90.0, monthly_salary * 0.16)
                ):
                    score += 0.7
                    reasons.append("early repeated payments to one counterparty under phishing pressure")

                previous_time = timestamp

                if phishing_events:
                    min_hours_after = None
                    for evt in phishing_events:
                        delta_hours = (timestamp - evt).total_seconds() / 3600.0
                        if 0.0 <= delta_hours <= 14 * 24:
                            if min_hours_after is None or delta_hours < min_hours_after:
                                min_hours_after = delta_hours

                    if min_hours_after is not None:
                        if min_hours_after <= 48.0:
                            score += 1.4
                            reasons.append("close in time to suspicious phishing communication")
                        elif min_hours_after <= 7 * 24:
                            score += 0.9
                            reasons.append("within 7 days of suspicious phishing communication")
                        elif min_hours_after <= 14 * 24 and amount >= max(140.0, monthly_salary * 0.2):
                            score += 0.5
                            reasons.append("within 14 days of phishing signal")

                        if (
                            min_hours_after <= 72.0
                            and tx_type in {"transfer", "e-commerce"}
                            and amount >= max(95.0, monthly_salary * 0.16)
                        ):
                            score += 0.9
                            reasons.append("high-risk channel shortly after phishing signal")

            balance_raw = str(tx.get("balance_after", "")).strip()
            if balance_raw:
                current_balance = _safe_float(balance_raw)
                if current_balance < 0:
                    score += 1.7
                    reasons.append("post-transaction balance is negative")

                if previous_balance is not None:
                    if previous_balance > 0 and current_balance < previous_balance * 0.35:
                        if amount > max(100.0, monthly_salary * 0.2):
                            score += 1.0
                            reasons.append("sharp balance drop after transaction")

                previous_balance = current_balance

            description = str(tx.get("description", ""))
            description_norm = _normalize_text(description)
            keyword_hits = [kw for kw in SUSPICIOUS_DESC_KEYWORDS if kw in description_norm]
            if keyword_hits:
                score += min(1.6, 0.5 * len(keyword_hits))
                reasons.append(f"suspicious description terms: {', '.join(keyword_hits[:3])}")

            if _extract_urls(description):
                score += 0.8
                reasons.append("description includes URL")

            if comm_risk >= 5.0 and amount > max(120.0, monthly_salary * 0.25):
                score += 0.7
                reasons.append("citizen has elevated phishing exposure")

            recipient_risk = float(recipient_risk_by_counterparty.get(counterparty, 0.0))
            if recipient_risk >= 1.0:
                score += min(1.7, recipient_risk * 0.9)
                reasons.append("counterparty is globally risky across multiple citizens")
                if is_new_counterparty:
                    score += 0.6
                    reasons.append("first interaction with a globally risky counterparty")

            # Legitimate-pattern dampening to keep precision stable while recall increases.
            if "rent payment" in description_norm:
                score -= 1.3
                mitigation_signals.append("rent-like recurring pattern")

            if (
                tx_type == "direct debit"
                and amount <= max(130.0, monthly_salary * 0.12)
                and counterparty_seen[counterparty] >= 2
            ):
                score -= 0.7
                mitigation_signals.append("small recurring direct-debit pattern")

            if (
                tx_type == "in-person payment"
                and location_norm
                and location_norm in known_cities
                and amount < 70.0
                and not keyword_hits
            ):
                score -= 0.45
                mitigation_signals.append("small local in-person routine spend")

            score = max(0.0, score)

            counterparty_seen[counterparty] += 1

            deduped_reasons: list[str] = []
            for reason in reasons:
                if reason not in deduped_reasons:
                    deduped_reasons.append(reason)

            deduped_mitigations: list[str] = []
            for signal in mitigation_signals:
                if signal not in deduped_mitigations:
                    deduped_mitigations.append(signal)

            risk_by_txn[tid] = {
                "transaction_id": tid,
                "citizen_id": cid,
                "score": round(score, 4),
                "risk_reasons": deduped_reasons[:6],
                "legitimacy_signals": deduped_mitigations[:4],
                "amount": amount,
                "timestamp": str(tx.get("timestamp", "")),
                "transaction_type": tx_type,
                "payment_method": payment_method,
                "counterparty": counterparty,
                "is_new_counterparty": bool(is_new_counterparty),
            }

            all_scores.append(score)

        citizen_tx_ids = [
            str(tx.get("transaction_id", "")).strip()
            for tx in outgoing
            if str(tx.get("transaction_id", "")).strip()
        ]
        citizen_tx_ids = [tid for tid in citizen_tx_ids if tid in risk_by_txn]

        ranked_citizen_tx = sorted(
            citizen_tx_ids,
            key=lambda tid: float(risk_by_txn[tid]["score"]),
            reverse=True,
        )

        citizen_scores = [float(risk_by_txn[tid]["score"]) for tid in ranked_citizen_tx]
        citizen_threshold = max(1.9, _quantile(citizen_scores, 0.84) if citizen_scores else 1.9)

        suspicious_tx = [tid for tid in ranked_citizen_tx if float(risk_by_txn[tid]["score"]) >= citizen_threshold]

        citizen_overview[cid] = {
            "citizen_id": cid,
            "sent_count": len(outgoing),
            "received_count": len(incoming),
            "annual_salary": salary,
            "monthly_salary_approx": round(monthly_salary, 2),
            "amount_mean": round(statistics.mean(amounts), 2) if amounts else 0.0,
            "amount_median": round(median_amount, 2),
            "amount_q90": round(q90_amount, 2),
            "night_transactions": night_count,
            "night_ratio": round((night_count / len(outgoing)), 3) if outgoing else 0.0,
            "transaction_types": dict(type_counts),
            "payment_methods": dict(method_counts),
            "communication_risk": comm_summary.get(cid, {}),
            "max_risk_score": round(max(citizen_scores), 4) if citizen_scores else 0.0,
            "risk_threshold": round(citizen_threshold, 4),
            "candidate_transaction_ids": suspicious_tx[:50],
            "top_risky_transactions": [
                {
                    "transaction_id": tid,
                    "score": risk_by_txn[tid]["score"],
                    "amount": risk_by_txn[tid]["amount"],
                    "type": risk_by_txn[tid]["transaction_type"],
                    "time": risk_by_txn[tid]["timestamp"],
                    "reasons": risk_by_txn[tid]["risk_reasons"],
                }
                for tid in ranked_citizen_tx[:15]
            ],
        }

    ranked_txn_ids = sorted(
        risk_by_txn.keys(),
        key=lambda tid: float(risk_by_txn[tid]["score"]),
        reverse=True,
    )

    global_threshold = max(1.8, _quantile(all_scores, 0.90) if all_scores else 1.8)
    global_high_risk_ids = [
        tid for tid in ranked_txn_ids if float(risk_by_txn[tid]["score"]) >= global_threshold
    ]

    floor_count = max(6, int(len(ranked_txn_ids) * 0.03))
    if len(global_high_risk_ids) < floor_count:
        global_high_risk_ids = ranked_txn_ids[:floor_count]

    max_count = max(1, int(len(ranked_txn_ids) * 0.35))
    if len(global_high_risk_ids) > max_count:
        global_high_risk_ids = global_high_risk_ids[:max_count]

    citizen_priority = sorted(
        citizen_overview.keys(),
        key=lambda cid: float(citizen_overview[cid].get("max_risk_score", 0.0)),
        reverse=True,
    )

    _DATA.clear()
    _DATA.update(
        {
            "transactions": transactions,
            "users": users,
            "locations": locations,
            "sms_rows": sms_rows,
            "mail_rows": mail_rows,
            "iban_to_user": iban_to_user,
            "citizen_to_user": citizen_to_user,
            "citizen_to_iban": citizen_to_iban,
            "citizen_ids": sorted(citizen_to_user.keys()),
            "txns_by_sender": dict(txns_by_sender),
            "txns_by_recipient": dict(txns_by_recipient),
            "locs_by_citizen": dict(locs_by_citizen),
            "sms_by_citizen": dict(sms_by_citizen),
            "mails_by_citizen": dict(mails_by_citizen),
            "comm_summary": comm_summary,
            "phishing_events_by_citizen": {
                cid: [evt.isoformat() for evt in events]
                for cid, events in phishing_events_by_citizen.items()
            },
            "recipient_risk_by_counterparty": recipient_risk_by_counterparty,
            "risk_by_txn": risk_by_txn,
            "citizen_overview": citizen_overview,
            "ranked_txn_ids": ranked_txn_ids,
            "global_high_risk_ids": global_high_risk_ids,
            "global_threshold": round(global_threshold, 4),
            "citizen_priority": citizen_priority,
            "all_txn_ids": {
                str(t.get("transaction_id", "")).strip()
                for t in transactions
                if str(t.get("transaction_id", "")).strip()
            },
            "flagged_transactions": set(),
        }
    )

    return {
        "citizens": len(_DATA["citizen_ids"]),
        "transactions": len(transactions),
        "location_pings": len(locations),
        "sms": len(sms_rows),
        "mails": len(mail_rows),
        "high_risk_candidates": len(global_high_risk_ids),
    }


# ---------------------------------------------------------------------------
# Tools exposed to the LLM
# ---------------------------------------------------------------------------


@tool
def list_citizens() -> str:
    """List all citizens with role, salary, and compact risk indicators.
    Use this first to understand who to investigate before deep-dives."""
    if not _DATA:
        return "Dataset not loaded."

    lines = [
        (
            f"Dataset has {len(_DATA['citizen_ids'])} citizens and "
            f"{len(_DATA['transactions'])} transactions."
        ),
        f"Global deterministic risk threshold: {_DATA['global_threshold']}",
        "",
    ]

    for cid in _DATA["citizen_ids"]:
        user = _DATA["citizen_to_user"].get(cid, {})
        ov = _DATA["citizen_overview"].get(cid, {})
        risk = ov.get("max_risk_score", 0.0)
        cand = len(ov.get("candidate_transaction_ids", []))
        comm = ov.get("communication_risk", {})
        comm_score = comm.get("risk_score", 0.0)
        lines.append(
            (
                f"{cid}: {user.get('first_name', '')} {user.get('last_name', '')}, "
                f"job={user.get('job', '?')}, salary={user.get('salary', '?')}, "
                f"sent={ov.get('sent_count', 0)}, recv={ov.get('received_count', 0)}, "
                f"max_risk={risk}, candidates={cand}, comm_risk={comm_score}"
            )
        )

    return "\n".join(lines)


@tool
def get_global_risk_overview(limit: int = 80) -> str:
    """Return the top globally suspicious transactions from deterministic triage.
    Call this early to prioritize where the LLM should reason first."""
    if not _DATA:
        return "Dataset not loaded."

    capped = max(1, min(int(limit), 200))

    top_ids = _DATA["global_high_risk_ids"][:capped]
    top_tx = []
    for tid in top_ids:
        risk = _DATA["risk_by_txn"].get(tid, {})
        top_tx.append(
            {
                "transaction_id": tid,
                "citizen_id": risk.get("citizen_id"),
                "score": risk.get("score"),
                "amount": risk.get("amount"),
                "transaction_type": risk.get("transaction_type"),
                "payment_method": risk.get("payment_method"),
                "timestamp": risk.get("timestamp"),
                "counterparty": risk.get("counterparty"),
                "reasons": risk.get("risk_reasons", []),
            }
        )

    payload = {
        "dataset_summary": {
            "citizens": len(_DATA["citizen_ids"]),
            "transactions": len(_DATA["transactions"]),
            "global_risk_threshold": _DATA["global_threshold"],
            "high_risk_candidates_total": len(_DATA["global_high_risk_ids"]),
        },
        "investigation_priority_citizens": _DATA["citizen_priority"],
        "top_risky_transactions": top_tx,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


@tool
def get_citizen_profile(citizen_id: str) -> str:
    """Get full personal profile for one citizen (salary, job, residence, description)."""
    cid = citizen_id.strip()
    profile = _DATA.get("citizen_to_user", {}).get(cid)
    if not profile:
        return f"No profile found for citizen '{cid}'."
    return json.dumps(profile, indent=2, ensure_ascii=False)


@tool
def get_citizen_risk_summary(citizen_id: str) -> str:
    """Get one citizen's behavioral risk summary and top suspicious transaction IDs.
    This is the primary per-citizen investigation tool."""
    cid = citizen_id.strip()
    overview = _DATA.get("citizen_overview", {}).get(cid)
    if not overview:
        return f"No risk summary found for citizen '{cid}'."

    return json.dumps(overview, indent=2, ensure_ascii=False)


@tool
def get_transaction_details(transaction_ids: str) -> str:
    """Get full details for a comma-separated list of transaction IDs.
    Use after triage to inspect specific suspicious transactions."""
    raw_ids = re.split(r"[,\s]+", transaction_ids or "")
    ids = [tid.strip() for tid in raw_ids if tid.strip()]
    ids = ids[:120]

    if not ids:
        return "No transaction IDs provided."

    by_id = {str(tx.get("transaction_id", "")).strip(): tx for tx in _DATA.get("transactions", [])}

    details: list[dict[str, Any]] = []
    missing: list[str] = []

    for tid in ids:
        tx = by_id.get(tid)
        if not tx:
            missing.append(tid)
            continue

        risk = _DATA.get("risk_by_txn", {}).get(tid, {})
        details.append(
            {
                "transaction_id": tid,
                "sender_id": tx.get("sender_id", ""),
                "recipient_id": tx.get("recipient_id", ""),
                "transaction_type": tx.get("transaction_type", ""),
                "amount": tx.get("amount", ""),
                "location": tx.get("location", ""),
                "payment_method": tx.get("payment_method", ""),
                "balance_after": tx.get("balance_after", ""),
                "description": tx.get("description", ""),
                "timestamp": tx.get("timestamp", ""),
                "risk_score": risk.get("score", 0.0),
                "risk_reasons": risk.get("risk_reasons", []),
                "legitimacy_signals": risk.get("legitimacy_signals", []),
                "is_new_counterparty": risk.get("is_new_counterparty", False),
            }
        )

    payload = {
        "requested": len(ids),
        "returned": len(details),
        "missing": missing[:20],
        "transactions": details,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


@tool
def get_citizen_location_summary(citizen_id: str) -> str:
    """Get mobility summary for a citizen: cities visited and distance from home."""
    cid = citizen_id.strip()

    user = _DATA.get("citizen_to_user", {}).get(cid)
    pings = _DATA.get("locs_by_citizen", {}).get(cid, [])

    if not user:
        return f"No user found for citizen '{cid}'."
    if not pings:
        return f"No location pings found for citizen '{cid}'."

    residence = user.get("residence", {})
    home_city = str(residence.get("city", "unknown"))
    home_lat = _safe_float(residence.get("lat", 0.0))
    home_lng = _safe_float(residence.get("lng", 0.0))

    city_counts: dict[str, int] = defaultdict(int)
    distances: list[float] = []

    for ping in pings:
        city = str(ping.get("city", "unknown"))
        city_counts[city] += 1

        d = _haversine_km(
            home_lat,
            home_lng,
            _safe_float(ping.get("lat", 0.0)),
            _safe_float(ping.get("lng", 0.0)),
        )
        distances.append(d)

    far_pings = [
        {
            "city": p.get("city", ""),
            "timestamp": p.get("timestamp", ""),
            "distance_km": round(d, 1),
        }
        for p, d in zip(pings, distances)
        if d > 50.0
    ]

    home_city_hits = city_counts.get(home_city, 0)
    home_city_ratio = (home_city_hits / len(pings)) if pings else 0.0

    payload = {
        "citizen_id": cid,
        "home_city": home_city,
        "total_pings": len(pings),
        "cities_visited": dict(sorted(city_counts.items(), key=lambda item: item[1], reverse=True)),
        "home_city_ratio": round(home_city_ratio, 3),
        "distance_from_home_km": {
            "mean": round(statistics.mean(distances), 2) if distances else 0.0,
            "max": round(max(distances), 2) if distances else 0.0,
        },
        "far_pings": far_pings[:20],
        "date_range": {
            "first": pings[0].get("timestamp", "") if pings else "",
            "last": pings[-1].get("timestamp", "") if pings else "",
        },
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


@tool
def get_citizen_communications(citizen_id: str, max_sms: int = 8, max_mails: int = 5) -> str:
    """Get SMS/email evidence for a citizen.
    Expensive tool: use only for high-risk or borderline investigations."""
    cid = citizen_id.strip()
    sms_list = _DATA.get("sms_by_citizen", {}).get(cid, [])
    mail_list = _DATA.get("mails_by_citizen", {}).get(cid, [])
    summary = _DATA.get("comm_summary", {}).get(cid, {})

    sms_cap = max(0, min(int(max_sms), 20))
    mail_cap = max(0, min(int(max_mails), 12))

    sms_samples = [s[:500] for s in sms_list[:sms_cap]]

    mail_samples: list[str] = []
    for mail in mail_list[:mail_cap]:
        compact = _strip_html(mail)
        if len(compact) > 900:
            compact = compact[:900] + " ...[truncated]"
        mail_samples.append(compact)

    payload = {
        "citizen_id": cid,
        "communication_summary": summary,
        "sms_samples": sms_samples,
        "mail_samples": mail_samples,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


@tool
def mark_fraudulent_transactions(transaction_ids: str) -> str:
    """Record final suspected fraudulent transaction IDs.
    Input must be a comma-separated list of transaction UUIDs."""
    raw_ids = re.split(r"[,\s]+", transaction_ids or "")
    ids = [tid.strip() for tid in raw_ids if tid.strip()]

    valid_ids = _DATA.get("all_txn_ids", set())

    confirmed: list[str] = []
    invalid: list[str] = []

    for tid in ids:
        if tid in valid_ids:
            _DATA["flagged_transactions"].add(tid)
            confirmed.append(tid)
        else:
            invalid.append(tid)

    msg = (
        f"Recorded {len(confirmed)} ID(s). "
        f"Total flagged so far: {len(_DATA.get('flagged_transactions', set()))}."
    )

    if invalid:
        msg += f" Invalid IDs skipped: {invalid[:8]}"

    return msg


# ---------------------------------------------------------------------------
# Non-tool utility API used by main.py / agent.py
# ---------------------------------------------------------------------------


def ingest_candidate_transaction_ids(candidate_ids: list[str]) -> int:
    """Validate and store candidate IDs from non-tool fallback paths."""
    valid = _DATA.get("all_txn_ids", set())
    before = len(_DATA.get("flagged_transactions", set()))

    for tid in candidate_ids:
        if tid in valid:
            _DATA["flagged_transactions"].add(tid)

    after = len(_DATA.get("flagged_transactions", set()))
    return max(0, after - before)


def get_flagged_transactions() -> list[str]:
    """Return sorted flagged transaction IDs."""
    return sorted(_DATA.get("flagged_transactions", set()))


def get_fallback_transaction_ids(max_ratio: float = 0.08, min_count: int = 12) -> list[str]:
    """Deterministic fallback when the LLM fails to output valid IDs."""
    ranked = _DATA.get("ranked_txn_ids", [])
    if not ranked:
        return []

    total = len(_DATA.get("transactions", []))
    target = max(int(total * max(0.01, min(max_ratio, 0.30))), int(min_count))
    target = min(target, max(1, total - 1))

    candidates = _DATA.get("global_high_risk_ids", [])[:target]
    if len(candidates) < min_count:
        candidates = ranked[:target]

    return list(candidates)


def calibrate_flagged_transactions(
    candidate_ids: list[str],
    min_ratio: float = 0.012,
    target_ratio: float = 0.02,
    max_ratio: float = 0.18,
    min_count: int = 24,
) -> list[str]:
    """Calibrate a candidate fraud list using deterministic risk ranking.

    Strategy:
    - Keep valid LLM IDs.
    - If list is too short, expand with the highest-risk transactions first.
    - If list is too large, trim by risk ranking to contain false positives.
    """
    all_ids = _DATA.get("all_txn_ids", set())
    ranked = _DATA.get("ranked_txn_ids", [])
    high_risk = _DATA.get("global_high_risk_ids", [])
    high_risk_set = set(high_risk)
    risk_by_txn = _DATA.get("risk_by_txn", {})

    if not ranked:
        return []

    total = len(_DATA.get("transactions", []))
    if total <= 0:
        return []

    min_target = max(int(total * max(0.005, min_ratio)), int(min_count))
    target = max(min_target, int(total * max(min_ratio, target_ratio)))
    max_target = max(min_target, int(total * max(target_ratio, max_ratio)))

    ranked_scores = [float(risk_by_txn.get(tid, {}).get("score", 0.0)) for tid in ranked]
    strong_cutoff = max(2.8, _quantile(ranked_scores, 0.965) if ranked_scores else 2.8)
    strong_anchors = [
        tid
        for tid in ranked
        if float(risk_by_txn.get(tid, {}).get("score", 0.0)) >= strong_cutoff
    ]

    selected: list[str] = []
    seen: set[str] = set()

    for tid in candidate_ids:
        if tid in all_ids and tid not in seen:
            seen.add(tid)
            selected.append(tid)

    # Always keep a strong deterministic anchor set to avoid under-recall.
    anchor_target = max(12, int(total * 0.015))
    for tid in strong_anchors[: max(anchor_target, 24)]:
        if tid in seen:
            continue
        seen.add(tid)
        selected.append(tid)

    # Ensure minimum coverage of global high-risk candidates even if LLM is conservative.
    high_risk_cover_target = max(20, int(total * 0.022))
    selected_high_risk = sum(1 for tid in selected if tid in high_risk_set)
    if selected_high_risk < high_risk_cover_target:
        for tid in high_risk:
            if tid in seen:
                continue
            seen.add(tid)
            selected.append(tid)
            selected_high_risk += 1
            if selected_high_risk >= high_risk_cover_target:
                break

    if len(selected) < min_target:
        for pool in (high_risk, ranked):
            for tid in pool:
                if tid in seen:
                    continue
                seen.add(tid)
                selected.append(tid)
                if len(selected) >= target:
                    break
            if len(selected) >= target:
                break

    rank_pos = {tid: idx for idx, tid in enumerate(ranked)}
    selected.sort(key=lambda tid: rank_pos.get(tid, 10**9))

    if len(selected) > max_target:
        selected = selected[:max_target]

    return selected


def get_all_tools() -> list:
    """Return all tools registered for the ReAct agent."""
    return [
        list_citizens,
        get_global_risk_overview,
        get_citizen_profile,
        get_citizen_risk_summary,
        get_transaction_details,
        get_citizen_location_summary,
        get_citizen_communications,
        mark_fraudulent_transactions,
    ]
