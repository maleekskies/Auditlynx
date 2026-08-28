"""
Core logic for the phishing email analyzer.

Takes raw email source (headers + body, .eml-style text) and runs a set
of heuristic checks: auth results (SPF/DKIM/DMARC), sender/domain
mismatches, suspicious links, urgency language, header anomalies, and
risky attachment mentions.

This is a heuristic triage tool, not a verdict machine — it surfaces
signals for a human analyst to weigh, it doesn't claim certainty.
"""
import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import getaddresses, parseaddr
from typing import Optional
from urllib.parse import urlparse

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_PASS = "pass"

_POINTS = {SEVERITY_HIGH: 30, SEVERITY_MEDIUM: 15, SEVERITY_LOW: 5}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

RISKY_ATTACHMENT_EXT = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".msi",
    ".hta", ".wsf", ".lnk", ".iso", ".img", ".com", ".pif",
}

URGENCY_PHRASES = [
    r"verify your account", r"account will be suspended", r"act now",
    r"immediate action required", r"your account has been (locked|limited|suspended)",
    r"unusual (sign[- ]?in|login) activity", r"confirm your (identity|password|details)",
    r"click here immediately", r"within 24 hours", r"final notice",
    r"payment (failed|declined)", r"update your (billing|payment) information",
    r"unauthorized (access|transaction)", r"security alert", r"limited time",
    r"failure to (respond|comply)", r"this is your last", r"avoid (suspension|termination)",
    r"as soon as possible", r"urgent(ly)?", r"reset your password",
]

COMMON_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "bankofamerica",
    "chase", "wellsfargo", "dropbox", "docusign", "linkedin", "facebook", "instagram",
    "office365", "outlook", "irs", "usps", "fedex", "dhl", "coinbase",
]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    category: str  # authentication | sender | links | language | headers | attachments
    recommendation: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class EmailAnalysisResult:
    risk_score: int
    risk_label: str
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None


def _risk_label(score: int) -> str:
    if score >= 70:
        return "High risk"
    if score >= 35:
        return "Suspicious"
    if score >= 10:
        return "Low risk"
    return "No strong indicators"


def analyze(raw_email: str) -> EmailAnalysisResult:
    raw_email = raw_email.strip()
    if not raw_email:
        return EmailAnalysisResult(risk_score=0, risk_label="No strong indicators",
                                    error="Paste the raw email source (headers + body) to analyze.")

    msg = message_from_string(raw_email)
    findings: list[Finding] = []

    findings.extend(_check_auth_results(msg))
    findings.extend(_check_sender_mismatch(msg))
    findings.extend(_check_header_anomalies(msg, raw_email))

    body_text, body_html = _extract_body(msg)
    findings.extend(_check_links(body_html, body_text))
    findings.extend(_check_urgency_language(body_text or _strip_html(body_html)))
    findings.extend(_check_attachments(msg))

    score = 0
    for f in findings:
        score += _POINTS.get(f.severity, 0)
    score = min(score, 100)

    from_header = msg.get("From", "")
    subject = msg.get("Subject", "")

    return EmailAnalysisResult(
        risk_score=score,
        risk_label=_risk_label(score),
        findings=findings,
        summary={"from": from_header, "subject": subject},
    )


def _check_auth_results(msg) -> list:
    findings = []
    auth_results = msg.get_all("Authentication-Results", [])
    combined = " ".join(auth_results).lower()

    if not auth_results:
        findings.append(Finding(
            "auth_missing", "Authentication-Results header", SEVERITY_MEDIUM,
            "No Authentication-Results header found — SPF/DKIM/DMARC outcome can't be verified from these headers "
            "(it may have been stripped, or this isn't the full original source).",
            "authentication",
            "Ask the reporting user for the full original .eml source, or check with the receiving mail server's logs.",
        ))
        return findings

    for mech, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        match = re.search(rf"{mech}=(\w+)", combined)
        if not match:
            findings.append(Finding(f"{mech}_missing", f"{label} result", SEVERITY_LOW,
                                     f"No {label} result present in Authentication-Results.", "authentication"))
            continue
        result = match.group(1)
        if result in ("fail", "softfail", "permerror"):
            findings.append(Finding(f"{mech}_fail", f"{label} failed", SEVERITY_HIGH,
                                     f"{label} check returned '{result}' — the sending source is not authorized or the message was altered/spoofed.",
                                     "authentication",
                                     f"Treat this message as likely spoofed. Verify with the purported sender through a separate channel.",
                                     raw_value=result))
        elif result == "none":
            findings.append(Finding(f"{mech}_none", f"{label} not evaluated", SEVERITY_LOW,
                                     f"{label} = none (no policy published or nothing to check).", "authentication",
                                     raw_value=result))
        else:
            findings.append(Finding(f"{mech}_pass", f"{label} passed", SEVERITY_PASS,
                                     f"{label} check passed.", "authentication", raw_value=result))
    return findings


def _check_sender_mismatch(msg) -> list:
    findings = []
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    from_name, from_addr = parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    if return_path:
        _, rp_addr = parseaddr(return_path)
        rp_domain = rp_addr.split("@")[-1].lower() if "@" in rp_addr else ""
        if rp_domain and from_domain and rp_domain != from_domain and not _same_org(rp_domain, from_domain):
            findings.append(Finding(
                "return_path_mismatch", "Return-Path domain differs from From domain", SEVERITY_MEDIUM,
                f"From domain is '{from_domain}' but Return-Path domain is '{rp_domain}' — bounces go somewhere "
                "other than where the message claims to originate, which is common in spoofed mail.",
                "sender",
                "Compare both domains against the organization's known mail infrastructure.",
                raw_value=f"From: {from_domain} / Return-Path: {rp_domain}",
            ))

    if reply_to:
        _, rt_addr = parseaddr(reply_to)
        rt_domain = rt_addr.split("@")[-1].lower() if "@" in rt_addr else ""
        if rt_domain and from_domain and rt_domain != from_domain and not _same_org(rt_domain, from_domain):
            findings.append(Finding(
                "reply_to_mismatch", "Reply-To domain differs from From domain", SEVERITY_HIGH,
                f"Message displays From '{from_domain}' but replies are routed to '{rt_domain}' — a classic "
                "technique to redirect victim replies to an attacker-controlled mailbox.",
                "sender",
                "Do not reply. Confirm the discrepancy is expected before trusting this message.",
                raw_value=f"From: {from_domain} / Reply-To: {rt_domain}",
            ))

    if from_name and from_domain:
        for brand in COMMON_BRANDS:
            if brand in from_name.lower() and brand not in from_domain.replace("-", "").replace(".", ""):
                findings.append(Finding(
                    "brand_display_name", "Display name impersonates a known brand", SEVERITY_HIGH,
                    f"Display name references '{brand.title()}' but the sending domain ('{from_domain}') has no "
                    "relation to that brand — a common display-name spoofing pattern.",
                    "sender",
                    "Verify the sending domain against the brand's actual official domains.",
                    raw_value=from_header,
                ))
                break

    if not findings and not from_domain:
        findings.append(Finding("no_from", "No parseable From address", SEVERITY_LOW,
                                 "Couldn't parse a From address from the headers provided.", "sender"))

    return findings


def _same_org(domain_a: str, domain_b: str) -> bool:
    """Loose check: are these two domains likely the same organization (e.g. mail.foo.com vs foo.com)?"""
    def root(d):
        parts = d.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else d
    return root(domain_a) == root(domain_b)


def _check_header_anomalies(msg, raw_email: str) -> list:
    findings = []
    message_id = msg.get("Message-ID", "")
    from_header = msg.get("From", "")
    _, from_addr = parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    if message_id and from_domain:
        mid_domain_match = re.search(r"@([\w.-]+)>?$", message_id.strip())
        if mid_domain_match:
            mid_domain = mid_domain_match.group(1).lower()
            if mid_domain and not _same_org(mid_domain, from_domain):
                findings.append(Finding(
                    "message_id_mismatch", "Message-ID domain differs from From domain", SEVERITY_LOW,
                    f"Message-ID domain ('{mid_domain}') doesn't match the From domain ('{from_domain}'). "
                    "This happens legitimately with some mail platforms, but is also seen in spoofed mail.",
                    "headers",
                    raw_value=message_id,
                ))

    received_headers = msg.get_all("Received", [])
    if not received_headers:
        findings.append(Finding(
            "no_received", "No Received headers found", SEVERITY_LOW,
            "No Received header chain present — this may be a partial paste rather than the full original source.",
            "headers",
            "For a full analysis, paste the complete raw source including all Received headers.",
        ))
    elif len(received_headers) == 1:
        findings.append(Finding(
            "short_received_chain", "Unusually short Received chain", SEVERITY_LOW,
            "Only one Received header — legitimate mail typically hops through multiple servers.",
            "headers",
        ))

    if not findings:
        findings.append(Finding("headers_ok", "No obvious header anomalies", SEVERITY_PASS,
                                 "Message-ID and Received chain look unremarkable.", "headers"))

    return findings


def _extract_body(msg):
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                text = ""
            if ctype == "text/plain":
                text_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else str(msg.get_payload())
        except Exception:
            text = str(msg.get_payload())
        if msg.get_content_type() == "text/html":
            html_parts.append(text)
        else:
            text_parts.append(text)

    return "\n".join(text_parts), "\n".join(html_parts)


def _strip_html(html: str) -> str:
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _check_links(body_html: str, body_text: str) -> list:
    findings = []

    anchor_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    anchors = anchor_pattern.findall(body_html) if body_html else []

    all_urls = set(re.findall(r'https?://[^\s"\'<>]+', body_html + " " + body_text))

    mismatch_found = False
    for href, anchor_text in anchors:
        visible = _strip_html(anchor_text).strip()
        visible_url_match = re.search(r'https?://[^\s"\'<>]+', visible)
        if visible_url_match:
            visible_url = visible_url_match.group(0)
            href_domain = urlparse(href).netloc.lower()
            visible_domain = urlparse(visible_url).netloc.lower()
            if href_domain and visible_domain and href_domain != visible_domain:
                mismatch_found = True
                findings.append(Finding(
                    "link_text_mismatch", "Link text doesn't match destination", SEVERITY_HIGH,
                    f"Displayed link text points to '{visible_domain}' but the actual href goes to '{href_domain}' — "
                    "a common technique to disguise a malicious destination.",
                    "links",
                    "Hover/inspect before clicking; treat as malicious until the real domain is verified.",
                    raw_value=f"shown: {visible_domain} -> actual: {href_domain}",
                ))
    if mismatch_found:
        pass  # already added per-mismatch

    for url in all_urls:
        domain = urlparse(url).netloc.lower().split(":")[0]
        if not domain:
            continue

        if domain in URL_SHORTENERS:
            findings.append(Finding(
                f"shortener_{domain}", "URL shortener used", SEVERITY_MEDIUM,
                f"Link uses shortener '{domain}', which hides the true destination.", "links",
                "Expand the shortened URL in a sandboxed environment before visiting.", raw_value=url,
            ))

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            findings.append(Finding(
                f"ip_url_{domain}", "Link points directly to an IP address", SEVERITY_HIGH,
                f"Link resolves to a raw IP address ({domain}) rather than a domain name — unusual for legitimate "
                "corporate mail and common in phishing infrastructure.",
                "links", raw_value=url,
            ))

        if urlparse(url).scheme != "https":
            findings.append(Finding(
                f"http_url_{domain}", "Non-HTTPS link", SEVERITY_LOW,
                f"Link to '{domain}' is not HTTPS.", "links", raw_value=url,
            ))

        typosquat = _check_typosquat(domain)
        if typosquat:
            findings.append(Finding(
                f"typosquat_{domain}", "Possible lookalike/typosquat domain", SEVERITY_HIGH,
                f"Domain '{domain}' closely resembles '{typosquat}' but isn't an exact match — a common brand "
                "impersonation technique.",
                "links",
                f"Compare character-by-character against the real '{typosquat}' domain before trusting this link.",
                raw_value=url,
            ))

    if not all_urls:
        findings.append(Finding("no_links", "No links found in body", SEVERITY_PASS,
                                 "No http(s) links detected in the message body.", "links"))
    elif not any(f.severity != SEVERITY_PASS for f in findings):
        findings.append(Finding("links_clean", "No suspicious link patterns detected", SEVERITY_PASS,
                                 f"{len(all_urls)} link(s) found; none matched shortener, IP-literal, or typosquat patterns.",
                                 "links"))

    return findings


def _check_typosquat(domain: str) -> Optional[str]:
    core = domain
    for prefix in ("www.",):
        if core.startswith(prefix):
            core = core[len(prefix):]
    core_root = core.split(".")[0]

    for brand in COMMON_BRANDS:
        if core_root == brand:
            continue  # exact match to root, not a typosquat
        dist = _levenshtein(core_root, brand)
        if 0 < dist <= 2 and len(core_root) >= 4:
            return brand + ".com"
    return None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = curr
    return prev[-1]


def _check_urgency_language(text: str) -> list:
    findings = []
    if not text:
        return findings
    lower = text.lower()
    hits = []
    for pattern in URGENCY_PHRASES:
        if re.search(pattern, lower):
            hits.append(pattern.replace(r"\b", "").replace("(", "").replace(")", ""))

    if hits:
        severity = SEVERITY_HIGH if len(hits) >= 3 else SEVERITY_MEDIUM
        findings.append(Finding(
            "urgency_language", "Urgency / social-engineering language detected", severity,
            f"Found {len(hits)} phrase(s) associated with urgency-based social engineering: "
            f"{', '.join(sorted(set(hits))[:6])}.",
            "language",
            "Urgency and threat framing are pressure tactics designed to short-circuit careful review. Slow down.",
        ))
    else:
        findings.append(Finding("no_urgency", "No urgency language detected", SEVERITY_PASS,
                                 "No common urgency/social-engineering phrases matched.", "language"))
    return findings


def _check_attachments(msg) -> list:
    findings = []
    if not msg.is_multipart():
        return findings
    for part in msg.walk():
        disp = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if "attachment" not in disp and not filename:
            continue
        if not filename:
            continue
        lower_name = filename.lower()
        ext_match = re.search(r"(\.[a-z0-9]+)$", lower_name)
        ext = ext_match.group(1) if ext_match else ""

        double_ext = re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png)\.[a-z0-9]+$", lower_name)

        if ext in RISKY_ATTACHMENT_EXT:
            findings.append(Finding(
                f"risky_attachment_{filename}", "Potentially dangerous attachment", SEVERITY_HIGH,
                f"Attachment '{filename}' has an executable/script extension ({ext}).", "attachments",
                "Do not open. Submit to a sandboxed analysis environment if investigation is needed.",
                raw_value=filename,
            ))
        elif double_ext:
            findings.append(Finding(
                f"double_ext_{filename}", "Attachment uses double extension", SEVERITY_HIGH,
                f"Attachment '{filename}' uses a double extension, a technique to disguise a script/executable "
                "as a document or image.",
                "attachments", raw_value=filename,
            ))
        else:
            findings.append(Finding(
                f"attachment_{filename}", "Attachment present", SEVERITY_LOW,
                f"Message includes attachment '{filename}'.", "attachments", raw_value=filename,
            ))
    return findings
