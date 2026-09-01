"""
Core logic for the breach checker.

Checks an email address against XposedOrNot's free, keyless breach
database (https://xposedornot.com) and returns a plain-English
breakdown of what was found and what to do about it.

XposedOrNot doesn't store queried emails or log results, per their
posted privacy policy. This module doesn't store anything either.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_PASS = "pass"

API_URL = "https://api.xposedornot.com/v1/breach-analytics"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Data types that, if exposed, warrant a high-severity call-out.
_SENSITIVE_DATA_TYPES = {
    "passwords", "password", "financial data", "credit cards", "credit card",
    "bank account numbers", "social security numbers", "government id",
    "security questions and answers", "auth tokens",
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    recommendation: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class BreachCheckResult:
    email: str
    breach_count: int = 0
    findings: list = field(default_factory=list)
    error: Optional[str] = None


async def check_email(email_input: str) -> BreachCheckResult:
    email = email_input.strip()
    if not _EMAIL_RE.match(email):
        return BreachCheckResult(email=email_input, error="That doesn't look like a valid email address.")

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(API_URL, params={"email": email})
    except httpx.RequestError as exc:
        return BreachCheckResult(email=email, error=f"Couldn't reach the breach database: {exc.__class__.__name__}.")

    if resp.status_code == 404:
        return BreachCheckResult(
            email=email,
            breach_count=0,
            findings=[Finding(
                "no_breaches", "No known breaches found", SEVERITY_PASS,
                "This email address didn't turn up in any breaches in this database. "
                "This doesn't guarantee it's never been exposed anywhere — no single breach database is complete — "
                "but it's a good sign.",
            )],
        )

    if resp.status_code != 200:
        return BreachCheckResult(email=email, error=f"Breach database returned an unexpected response (HTTP {resp.status_code}).")

    try:
        data = resp.json()
    except ValueError:
        return BreachCheckResult(email=email, error="Got an unreadable response from the breach database.")

    exposed_breaches = _extract_breaches(data)

    if not exposed_breaches:
        return BreachCheckResult(
            email=email,
            breach_count=0,
            findings=[Finding(
                "no_breaches", "No known breaches found", SEVERITY_PASS,
                "This email address didn't turn up in any breaches in this database. "
                "This doesn't guarantee it's never been exposed anywhere — no single breach database is complete — "
                "but it's a good sign.",
            )],
        )

    findings: list[Finding] = []
    any_sensitive = False

    for breach in exposed_breaches:
        name = breach.get("breach") or breach.get("Breach") or breach.get("name") or "Unknown source"
        domain = breach.get("domain") or breach.get("Domain") or ""
        year = breach.get("xposed_date") or breach.get("XposedDate") or breach.get("year") or ""
        records = breach.get("xposed_records") or breach.get("XposedRecords") or ""
        data_types_raw = breach.get("xposed_data") or breach.get("XposedData") or ""
        data_types = [d.strip() for d in re.split(r"[;,]", str(data_types_raw)) if d.strip()]

        is_sensitive = any(dt.lower() in _SENSITIVE_DATA_TYPES for dt in data_types)
        if is_sensitive:
            any_sensitive = True

        severity = SEVERITY_HIGH if is_sensitive else SEVERITY_MEDIUM
        detail_parts = [f"Found in the '{name}' breach"]
        if domain:
            detail_parts.append(f" ({domain})")
        if year:
            detail_parts.append(f", dated {year}")
        if records:
            detail_parts.append(f". Roughly {records} records were exposed in total")
        if data_types:
            detail_parts.append(f". Data types exposed: {', '.join(data_types)}")

        findings.append(Finding(
            f"breach_{name}", f"Exposed in: {name}", severity,
            "".join(detail_parts) + ".",
            "Change the password used on this account, and anywhere else you reused it. "
            "Enable multi-factor authentication if the service offers it.",
            raw_value=str(data_types_raw) if data_types_raw else None,
        ))

    if any_sensitive:
        findings.insert(0, Finding(
            "action_needed", "Sensitive data was exposed — act on this", SEVERITY_HIGH,
            "At least one breach exposed sensitive data like passwords or financial information, not just an email address.",
            "Prioritize changing passwords tied to this email immediately, especially anywhere you reused the same password. "
            "Turn on MFA everywhere it's available.",
        ))

    return BreachCheckResult(email=email, breach_count=len(exposed_breaches), findings=findings)


def _extract_breaches(data: dict) -> list:
    """Best-effort extraction across the couple of shapes the API's docs show."""
    if not isinstance(data, dict):
        return []

    for key in ("ExposedBreaches", "exposedBreaches", "exposed_breaches"):
        val = data.get(key)
        if isinstance(val, dict):
            inner = val.get("breaches_details") or val.get("BreachesDetails")
            if isinstance(inner, list):
                return inner
        if isinstance(val, list):
            return val

    # Fallback: some responses nest everything under a single "breaches" list of names only.
    breaches = data.get("breaches")
    if isinstance(breaches, list):
        flat = []
        for item in breaches:
            if isinstance(item, list):
                flat.extend(item)
            else:
                flat.append(item)
        return [{"breach": name} for name in flat]

    return []
