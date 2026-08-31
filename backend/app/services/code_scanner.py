"""
Core logic for the code security scanner ("VibeCode Auditor").

Heuristic, pattern-based static analysis on pasted source code. Flags
common high-impact vulnerability classes: hardcoded secrets, injection
risks, insecure crypto, unsafe eval/exec, disabled TLS verification,
overly permissive CORS, and a few others.

This is pattern matching, not a real AST-based analyzer — it will
have false positives and false negatives. It's meant to catch the
common, well-known mistakes quickly, not replace a proper security
review or tools like Semgrep/CodeQL for anything going to production.
"""
import re
from dataclasses import dataclass, field
from typing import Optional

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_PASS = "pass"

_POINTS = {SEVERITY_HIGH: 25, SEVERITY_MEDIUM: 12, SEVERITY_LOW: 5}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    category: str
    recommendation: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class CodeScanResult:
    risk_score: int
    risk_label: str
    findings: list = field(default_factory=list)
    lines_scanned: int = 0
    error: Optional[str] = None


def _risk_label(score: int) -> str:
    if score >= 60:
        return "High risk"
    if score >= 25:
        return "Needs attention"
    if score >= 8:
        return "Minor issues"
    return "No obvious issues found"


# Each rule: (id, title, category, severity, regex, recommendation)
_RULES = [
    (
        "hardcoded_aws_key", "Hardcoded AWS access key", "secrets", SEVERITY_HIGH,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Never commit AWS keys. Use environment variables or a secrets manager (AWS Secrets Manager, Vault), and rotate this key immediately since it's now exposed.",
    ),
    (
        "hardcoded_generic_secret", "Hardcoded API key / secret / password", "secrets", SEVERITY_HIGH,
        re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
        "Move this into an environment variable (.env file, excluded from git) or a secrets manager. If this was ever committed to a real repo, rotate the credential.",
    ),
    (
        "private_key_block", "Embedded private key", "secrets", SEVERITY_HIGH,
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private keys should never be in source code. Load from a secure file path or secrets manager outside version control, and rotate this key.",
    ),
    (
        "sql_string_concat", "Possible SQL injection via string building", "injection", SEVERITY_HIGH,
        re.compile(r"(?i)(execute|cursor\.execute|query)\s*\(\s*[\"'].*?(\+|%s|\{.*?\}|f[\"'])"),
        "Use parameterized queries / prepared statements (e.g. cursor.execute(query, (param,))) instead of building SQL with string concatenation or f-strings.",
    ),
    (
        "eval_usage", "Use of eval()", "unsafe-execution", SEVERITY_HIGH,
        re.compile(r"\beval\s*\("),
        "eval() executes arbitrary code from its input. If you're parsing data, use json.loads or a proper parser instead; if you truly need dynamic execution, sandbox it heavily.",
    ),
    (
        "exec_usage", "Use of exec()", "unsafe-execution", SEVERITY_HIGH,
        re.compile(r"\bexec\s*\("),
        "exec() runs arbitrary code. Avoid running dynamic strings as code, especially anything derived from user input.",
    ),
    (
        "shell_injection_py", "Shell command built from variables (possible command injection)", "injection", SEVERITY_HIGH,
        re.compile(r"(?i)(os\.system|subprocess\.(call|run|Popen))\s*\([^)]*(\+|f[\"']|%s)"),
        "Avoid building shell commands via string concatenation. Pass arguments as a list (subprocess.run([...], shell=False)) and never pass shell=True with untrusted input.",
    ),
    (
        "innerhtml_assignment", "Direct innerHTML assignment (possible XSS)", "xss", SEVERITY_MEDIUM,
        re.compile(r"\.innerHTML\s*="),
        "Assigning to innerHTML with untrusted/user-controlled data enables XSS. Use textContent for plain text, or sanitize with a library like DOMPurify before inserting HTML.",
    ),
    (
        "dangerously_set_innerhtml", "React dangerouslySetInnerHTML usage", "xss", SEVERITY_MEDIUM,
        re.compile(r"dangerouslySetInnerHTML"),
        "Confirm the HTML source is fully trusted or sanitized (e.g. via DOMPurify). This prop bypasses React's built-in XSS protection.",
    ),
    (
        "weak_hash_md5", "MD5 used (weak hash)", "crypto", SEVERITY_MEDIUM,
        re.compile(r"(?i)\bmd5\s*\("),
        "MD5 is broken for security purposes. For passwords use bcrypt/argon2/scrypt; for general hashing use SHA-256 or better.",
    ),
    (
        "weak_hash_sha1", "SHA-1 used (weak hash)", "crypto", SEVERITY_LOW,
        re.compile(r"(?i)\bsha1\s*\("),
        "SHA-1 is deprecated for security-sensitive use. Prefer SHA-256 or higher; for passwords use bcrypt/argon2/scrypt instead of a general-purpose hash.",
    ),
    (
        "tls_verify_disabled", "TLS/SSL certificate verification disabled", "transport-security", SEVERITY_HIGH,
        re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        "Disabling certificate verification allows man-in-the-middle attacks. Only disable for local testing against known-safe hosts, never in code that could run against production.",
    ),
    (
        "cors_wildcard_credentials", "Wildcard CORS combined with credentials", "cors", SEVERITY_HIGH,
        re.compile(r"(?i)allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\].*allow_credentials\s*=\s*True", re.DOTALL),
        "allow_origins=['*'] with allow_credentials=True is both a security risk and invalid per the CORS spec in most browsers. List specific trusted origins instead.",
    ),
    (
        "cors_wildcard", "Wildcard CORS origin", "cors", SEVERITY_MEDIUM,
        re.compile(r"(?i)(Access-Control-Allow-Origin[\"']?\s*[:=]\s*[\"']\*[\"']|allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\])"),
        "A wildcard origin lets any website make authenticated requests to this API. Restrict to your actual frontend domain(s) before going to production.",
    ),
    (
        "debug_mode_on", "Debug mode enabled", "configuration", SEVERITY_MEDIUM,
        re.compile(r"(?i)\b(debug\s*=\s*True|DEBUG\s*=\s*true|app\.debug\s*=\s*true)\b"),
        "Debug mode often exposes stack traces, source code, and environment details to visitors. Ensure this is off in any production deployment.",
    ),
    (
        "insecure_random_for_security", "Non-cryptographic random used in a security-sensitive spot", "crypto", SEVERITY_MEDIUM,
        re.compile(r"(?i)(token|secret|password|otp|reset).{0,20}=\s*.*\b(Math\.random\(\)|random\.random\(\)|random\.randint\()"),
        "Math.random() / random.random() are not cryptographically secure. Use crypto.randomBytes (Node), secrets module (Python), or an equivalent CSPRNG for anything security-sensitive.",
    ),
    (
        "cookie_missing_flags", "Cookie set without security flags", "session", SEVERITY_LOW,
        re.compile(r"(?i)(set-cookie|document\.cookie)\s*[:=].*(?!.*(secure|httponly))", re.DOTALL),
        "Ensure session/auth cookies set the Secure, HttpOnly, and SameSite attributes to reduce theft and CSRF risk.",
    ),
    (
        "hardcoded_default_creds", "Hardcoded default username/password pair", "secrets", SEVERITY_MEDIUM,
        re.compile(r"(?i)(username|user)\s*[:=]\s*['\"]admin['\"].{0,60}(password|pwd)\s*[:=]\s*['\"][^'\"]+['\"]", re.DOTALL),
        "Default admin credentials in source code are a common way real deployments get compromised. Require credentials to be set via environment/config at deploy time, never shipped as defaults.",
    ),
    (
        "open_redirect", "Possible open redirect", "other", SEVERITY_LOW,
        re.compile(r"(?i)(redirect|location\.href)\s*\(?\s*=?\s*(req\.query|request\.args|params\[)"),
        "Redirecting to a URL taken directly from user input can be abused for phishing. Validate against an allowlist of permitted destinations before redirecting.",
    ),
]


def scan_code(code: str) -> CodeScanResult:
    code = code.strip("\n")
    if not code.strip():
        return CodeScanResult(risk_score=0, risk_label="No obvious issues found",
                               error="Paste some code to scan.")

    lines = code.split("\n")
    findings: list[Finding] = []
    seen_rule_lines = set()

    for rule_id, title, category, severity, pattern, recommendation in _RULES:
        for match in pattern.finditer(code):
            line_no = code[: match.start()].count("\n") + 1
            key = (rule_id, line_no)
            if key in seen_rule_lines:
                continue
            seen_rule_lines.add(key)

            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else None
            if snippet and len(snippet) > 140:
                snippet = snippet[:140] + "…"

            findings.append(Finding(
                id=f"{rule_id}_{line_no}",
                title=title,
                severity=severity,
                detail=f"Matched a known risky pattern for this issue type.",
                category=category,
                recommendation=recommendation,
                line=line_no,
                snippet=snippet,
            ))

    score = 0
    for f in findings:
        score += _POINTS.get(f.severity, 0)
    score = min(score, 100)

    if not findings:
        findings.append(Finding(
            "clean", "No known risky patterns matched", SEVERITY_PASS,
            "None of the built-in heuristic checks matched this code. This does not mean the code is fully secure — "
            "only that it didn't trip any of the specific patterns this scanner looks for.",
            "general",
        ))

    return CodeScanResult(
        risk_score=score,
        risk_label=_risk_label(score),
        findings=findings,
        lines_scanned=len(lines),
    )
