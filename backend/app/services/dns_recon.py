"""
Core logic for the DNS & Domain Recon module.

Pulls DNS records (A, MX, NS, SPF/DMARC via TXT) using Cloudflare's
DNS-over-HTTPS JSON API, and domain registration/age info via RDAP
(no extra dependencies needed — both are plain HTTPS/JSON).
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_PASS = "pass"

DOH_URL = "https://cloudflare-dns.com/dns-query"
RDAP_URL = "https://rdap.org/domain/{domain}"


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    category: str  # registration | dns | email-auth
    recommendation: Optional[str] = None
    raw_value: Optional[str] = None


@dataclass
class DomainReconResult:
    domain: str
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None


def _clean_domain(raw: str) -> str:
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0]
    raw = raw.split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


async def _doh_query(client: httpx.AsyncClient, name: str, record_type: str) -> list:
    resp = await client.get(
        DOH_URL,
        params={"name": name, "type": record_type},
        headers={"Accept": "application/dns-json"},
    )
    if resp.status_code != 200:
        return []
    data = resp.json()
    return data.get("Answer", [])


async def recon_domain(domain_input: str) -> DomainReconResult:
    domain = _clean_domain(domain_input)
    if not domain or "." not in domain:
        return DomainReconResult(domain=domain_input, error="That doesn't look like a valid domain.")

    findings: list[Finding] = []
    summary = {}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            a_records = await _doh_query(client, domain, "A")
            mx_records = await _doh_query(client, domain, "MX")
            ns_records = await _doh_query(client, domain, "NS")
            txt_records = await _doh_query(client, domain, "TXT")
            dmarc_records = await _doh_query(client, f"_dmarc.{domain}", "TXT")

            rdap_data = None
            try:
                rdap_resp = await client.get(RDAP_URL.format(domain=domain), follow_redirects=True)
                if rdap_resp.status_code == 200:
                    rdap_data = rdap_resp.json()
            except httpx.RequestError:
                pass

    except httpx.RequestError as exc:
        return DomainReconResult(domain=domain, error=f"Couldn't complete lookups: {exc.__class__.__name__}.")

    # --- Registration age ---
    if rdap_data:
        reg_date = _extract_rdap_event(rdap_data, "registration")
        if reg_date:
            age_days = (datetime.now(timezone.utc) - reg_date).days
            summary["registered"] = reg_date.strftime("%Y-%m-%d")
            summary["age_days"] = age_days
            if age_days < 30:
                findings.append(Finding(
                    "domain_very_new", "Domain registered very recently", SEVERITY_HIGH,
                    f"This domain was registered only {age_days} day(s) ago ({reg_date.strftime('%Y-%m-%d')}). "
                    "Brand-new domains are disproportionately used for phishing and scam campaigns.",
                    "registration",
                    "Treat communications from this domain with extra scrutiny, especially anything requesting credentials or payment.",
                    raw_value=reg_date.strftime("%Y-%m-%d"),
                ))
            elif age_days < 180:
                findings.append(Finding(
                    "domain_new", "Domain registered relatively recently", SEVERITY_MEDIUM,
                    f"Registered {age_days} days ago ({reg_date.strftime('%Y-%m-%d')}). Not necessarily malicious, "
                    "but worth factoring in alongside other signals.",
                    "registration", raw_value=reg_date.strftime("%Y-%m-%d"),
                ))
            else:
                findings.append(Finding(
                    "domain_established", "Domain has an established registration history", SEVERITY_PASS,
                    f"Registered {reg_date.strftime('%Y-%m-%d')} ({age_days} days ago).",
                    "registration", raw_value=reg_date.strftime("%Y-%m-%d"),
                ))
        registrar = _extract_rdap_registrar(rdap_data)
        if registrar:
            summary["registrar"] = registrar
    else:
        findings.append(Finding(
            "rdap_unavailable", "Registration data unavailable", SEVERITY_LOW,
            "Couldn't retrieve RDAP registration data for this domain (may be a privacy-protected TLD or a lookup failure).",
            "registration",
        ))

    # --- A records ---
    if a_records:
        ips = [r["data"] for r in a_records if r.get("type") == 1]
        summary["a_records"] = ips
        findings.append(Finding(
            "a_records_found", "A records resolved", SEVERITY_PASS,
            f"Domain resolves to: {', '.join(ips)}", "dns", raw_value=", ".join(ips),
        ))
    else:
        findings.append(Finding(
            "no_a_records", "No A records found", SEVERITY_MEDIUM,
            "This domain has no IPv4 address records — it may not be actively hosting a website, or the domain doesn't exist as entered.",
            "dns",
        ))

    # --- MX records ---
    if mx_records:
        mx_list = [r["data"] for r in mx_records if r.get("type") == 15]
        summary["mx_records"] = mx_list
        findings.append(Finding(
            "mx_found", "Mail servers configured", SEVERITY_PASS,
            f"{len(mx_list)} MX record(s) found.", "dns", raw_value="; ".join(mx_list),
        ))
    else:
        findings.append(Finding(
            "no_mx", "No MX records found", SEVERITY_LOW,
            "No mail servers configured for this domain — it likely doesn't send/receive email directly.",
            "dns",
        ))

    # --- SPF ---
    spf_txt = next((r["data"] for r in txt_records if "v=spf1" in r.get("data", "")), None)
    if spf_txt:
        findings.append(Finding(
            "spf_present", "SPF record present", SEVERITY_PASS,
            "SPF is configured, meaning the domain publishes which mail servers are authorized to send on its behalf.",
            "email-auth", raw_value=spf_txt,
        ))
        if "+all" in spf_txt:
            findings.append(Finding(
                "spf_permissive", "SPF record allows any server to send mail", SEVERITY_HIGH,
                "This SPF record ends in '+all', meaning it authorizes ANY server to send mail as this domain — effectively no protection.",
                "email-auth",
                "Change to '-all' (hard fail) or at minimum '~all' (soft fail) once all legitimate senders are listed.",
                raw_value=spf_txt,
            ))
    else:
        findings.append(Finding(
            "no_spf", "No SPF record found", SEVERITY_MEDIUM,
            "Without SPF, receiving mail servers can't verify whether mail claiming to be from this domain is actually authorized — makes spoofing easier.",
            "email-auth",
            "Add a TXT record like: v=spf1 include:_spf.yourmailprovider.com -all",
        ))

    # --- DMARC ---
    dmarc_txt = next((r["data"] for r in dmarc_records if "v=DMARC1" in r.get("data", "")), None)
    if dmarc_txt:
        policy_match = re.search(r"p=(\w+)", dmarc_txt)
        policy = policy_match.group(1) if policy_match else "unknown"
        if policy == "none":
            findings.append(Finding(
                "dmarc_none", "DMARC present but set to monitor-only (p=none)", SEVERITY_MEDIUM,
                "DMARC is published but its policy is 'none', meaning spoofed mail failing checks is still delivered — only reports are generated, nothing is blocked.",
                "email-auth",
                "Once SPF/DKIM are confirmed working, move the policy to p=quarantine or p=reject.",
                raw_value=dmarc_txt,
            ))
        else:
            findings.append(Finding(
                "dmarc_enforced", f"DMARC enforced (policy: {policy})", SEVERITY_PASS,
                f"DMARC is actively enforcing a '{policy}' policy on mail that fails authentication.",
                "email-auth", raw_value=dmarc_txt,
            ))
    else:
        findings.append(Finding(
            "no_dmarc", "No DMARC record found", SEVERITY_MEDIUM,
            "Without DMARC, there's no policy telling receiving servers what to do with mail that fails SPF/DKIM — spoofed mail is more likely to reach inboxes.",
            "email-auth",
            f"Add a TXT record at _dmarc.{domain} like: v=DMARC1; p=quarantine; rua=mailto:you@{domain}",
        ))

    return DomainReconResult(domain=domain, findings=findings, summary=summary)


def _extract_rdap_event(rdap_data: dict, event_action: str) -> Optional[datetime]:
    for event in rdap_data.get("events", []):
        if event.get("eventAction") == event_action:
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except (ValueError, KeyError):
                continue
    return None


def _extract_rdap_registrar(rdap_data: dict) -> Optional[str]:
    for entity in rdap_data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        return item[3]
    return None
