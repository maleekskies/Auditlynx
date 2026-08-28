"""
Core logic for the security headers & config checker.

Fetches a target URL server-side (avoids browser CORS restrictions),
inspects the response headers and cookies, and grades the result.
"""
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_PASS = "pass"

# Points deducted from a 100-point scale per severity of missing/misconfigured check.
_DEDUCTIONS = {SEVERITY_HIGH: 20, SEVERITY_MEDIUM: 10, SEVERITY_LOW: 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # pass | low | medium | high
    detail: str
    recommendation: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class HeaderCheckResult:
    url: str
    final_url: str
    status_code: int
    grade: str
    score: int
    findings: list = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)
    error: Optional[str] = None


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw


async def fetch_and_check(url: str) -> HeaderCheckResult:
    target = _normalize_url(url)
    parsed = urlparse(target)
    if not parsed.netloc:
        return HeaderCheckResult(
            url=url, final_url=url, status_code=0, grade="F", score=0,
            error="That doesn't look like a valid URL or domain.",
        )

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
            resp = await client.get(target, headers={"User-Agent": "SecOpsToolkit-HeaderChecker/1.0"})
    except httpx.RequestError as exc:
        return HeaderCheckResult(
            url=url, final_url=url, status_code=0, grade="F", score=0,
            error=f"Couldn't reach that host: {exc.__class__.__name__}.",
        )

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []

    findings.append(_check_hsts(headers_lower, resp.url.scheme))
    findings.append(_check_csp(headers_lower))
    findings.append(_check_x_frame_options(headers_lower))
    findings.append(_check_x_content_type_options(headers_lower))
    findings.append(_check_referrer_policy(headers_lower))
    findings.append(_check_permissions_policy(headers_lower))
    findings.extend(_check_cookies(resp))
    findings.extend(_check_info_leakage(headers_lower))

    score = 100
    for f in findings:
        score -= _DEDUCTIONS.get(f.severity, 0)
    score = max(score, 0)

    return HeaderCheckResult(
        url=url,
        final_url=str(resp.url),
        status_code=resp.status_code,
        grade=_grade_from_score(score),
        score=score,
        findings=findings,
        raw_headers=dict(resp.headers),
    )


def _check_hsts(headers: dict, scheme: str) -> Finding:
    val = headers.get("strict-transport-security")
    if scheme != "https":
        return Finding("hsts", "HTTP Strict Transport Security (HSTS)", SEVERITY_MEDIUM,
                        "Site was reached over plain HTTP, so HSTS can't apply here.",
                        "Serve the site over HTTPS and add Strict-Transport-Security.")
    if not val:
        return Finding("hsts", "HTTP Strict Transport Security (HSTS)", SEVERITY_HIGH,
                        "No Strict-Transport-Security header — browsers can be downgraded to plain HTTP.",
                        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    max_age_match = re.search(r"max-age=(\d+)", val)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 15552000:  # 180 days
        return Finding("hsts", "HTTP Strict Transport Security (HSTS)", SEVERITY_LOW,
                        f"HSTS is present but max-age is short ({max_age}s).",
                        "Raise max-age to at least 15552000 (180 days), ideally 31536000 with preload.",
                        raw_value=val)
    return Finding("hsts", "HTTP Strict Transport Security (HSTS)", SEVERITY_PASS,
                    "HSTS is set with an adequate max-age.", raw_value=val)


def _check_csp(headers: dict) -> Finding:
    val = headers.get("content-security-policy")
    if not val:
        return Finding("csp", "Content-Security-Policy", SEVERITY_HIGH,
                        "No CSP header — the site has no defense-in-depth layer against XSS and data injection.",
                        "Start with a baseline policy, e.g. default-src 'self'; object-src 'none'; and tighten from there.")
    if "unsafe-inline" in val and "script-src" in val:
        return Finding("csp", "Content-Security-Policy", SEVERITY_MEDIUM,
                        "CSP is present but allows 'unsafe-inline' scripts, which weakens XSS protection significantly.",
                        "Move inline scripts to external files or use nonces/hashes instead of 'unsafe-inline'.",
                        raw_value=val)
    return Finding("csp", "Content-Security-Policy", SEVERITY_PASS,
                    "CSP is present and doesn't allow unsafe-inline scripts.", raw_value=val)


def _check_x_frame_options(headers: dict) -> Finding:
    val = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp:
        return Finding("xfo", "Clickjacking protection (X-Frame-Options / frame-ancestors)", SEVERITY_PASS,
                        "Clickjacking protection is handled via CSP's frame-ancestors directive.", raw_value=csp)
    if not val:
        return Finding("xfo", "X-Frame-Options", SEVERITY_MEDIUM,
                        "No X-Frame-Options (and no CSP frame-ancestors) — the site can be embedded in a hidden iframe for clickjacking.",
                        "Add X-Frame-Options: DENY or SAMEORIGIN, or a CSP frame-ancestors directive.")
    if val.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return Finding("xfo", "X-Frame-Options", SEVERITY_LOW,
                        f"X-Frame-Options is set to an unusual value: {val}",
                        "Use DENY or SAMEORIGIN.", raw_value=val)
    return Finding("xfo", "X-Frame-Options", SEVERITY_PASS, "Framing is restricted.", raw_value=val)


def _check_x_content_type_options(headers: dict) -> Finding:
    val = headers.get("x-content-type-options")
    if val and val.strip().lower() == "nosniff":
        return Finding("xcto", "X-Content-Type-Options", SEVERITY_PASS,
                        "MIME-sniffing is disabled.", raw_value=val)
    return Finding("xcto", "X-Content-Type-Options", SEVERITY_LOW,
                    "Missing or incorrect X-Content-Type-Options — browsers may MIME-sniff responses.",
                    "Add: X-Content-Type-Options: nosniff")


def _check_referrer_policy(headers: dict) -> Finding:
    val = headers.get("referrer-policy")
    if not val:
        return Finding("referrer", "Referrer-Policy", SEVERITY_LOW,
                        "No Referrer-Policy — full URLs (possibly with sensitive query params) may leak to third parties via the Referer header.",
                        "Add: Referrer-Policy: strict-origin-when-cross-origin")
    weak = {"unsafe-url"}
    if val.strip().lower() in weak:
        return Finding("referrer", "Referrer-Policy", SEVERITY_LOW,
                        f"Referrer-Policy is set to a permissive value: {val}",
                        "Prefer strict-origin-when-cross-origin or no-referrer.", raw_value=val)
    return Finding("referrer", "Referrer-Policy", SEVERITY_PASS, "A reasonable referrer policy is set.", raw_value=val)


def _check_permissions_policy(headers: dict) -> Finding:
    val = headers.get("permissions-policy")
    if not val:
        return Finding("permissions", "Permissions-Policy", SEVERITY_LOW,
                        "No Permissions-Policy — the site doesn't explicitly restrict browser features (camera, mic, geolocation, etc.) for embedded content.",
                        "Add a Permissions-Policy that disables features you don't use, e.g. camera=(), microphone=(), geolocation=().")
    return Finding("permissions", "Permissions-Policy", SEVERITY_PASS, "Permissions-Policy is set.", raw_value=val)


def _check_cookies(resp: httpx.Response) -> list:
    findings = []
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not cookies:
        raw = resp.headers.get("set-cookie")
        cookies = [raw] if raw else []

    if not cookies:
        return findings

    for i, cookie in enumerate(cookies):
        name_match = re.match(r"^([^=]+)=", cookie)
        name = name_match.group(1) if name_match else f"cookie_{i}"
        lower = cookie.lower()
        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")

        if issues:
            findings.append(Finding(
                f"cookie_{name}", f"Cookie: {name}", SEVERITY_MEDIUM,
                f"Cookie '{name}' is {', '.join(issues)}.",
                "Set Secure, HttpOnly, and SameSite=Lax/Strict on session and auth cookies.",
                raw_value=cookie,
            ))
        else:
            findings.append(Finding(
                f"cookie_{name}", f"Cookie: {name}", SEVERITY_PASS,
                f"Cookie '{name}' has Secure, HttpOnly, and SameSite set.", raw_value=cookie,
            ))
    return findings


def _check_info_leakage(headers: dict) -> list:
    findings = []
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        val = headers.get(h)
        if val:
            findings.append(Finding(
                f"leak_{h}", f"Information disclosure: {h}", SEVERITY_LOW,
                f"The '{h}' header reveals server/framework details ({val}), which can help an attacker fingerprint the stack.",
                f"Suppress or generic-ize the {h} header at the proxy/server level.",
                raw_value=val,
            ))
    return findings
