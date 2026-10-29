"""
Heuristic URL risk analysis.

SAFETY CONTRACT
---------------
* This module only *parses* the URL string. It never opens a socket, performs
  DNS lookups, follows redirects or downloads page content.
* Nothing here proves that a URL is safe or malicious. Every result is an
  educational estimate built from observable structure.

SCORING SYSTEM (points are added, the total is capped at 100)
--------------------------------------------------------------
 +40  Username/`@` trick in the authority section ("trusted.com@evil.tld")
 +30  Punycode (IDN) host       - "xn--" labels, often look-alike domains
 +25  Host is a raw IP address  - legitimate sites use domain names
 +20  Embedded credentials      - "user:pass@host"
 +20  Domain imitates a brand   - brand name inside a different registered domain
 +30  Hexadecimal IP / odd host  - "0x7f.0.0.1", "2130706433", bare int-like host
 +15  High-risk file extension  - .exe, .scr, .apk, .zip, .docm, ...
 +15  Excessive subdomains      - 4 or more dots before the registered domain
 +12  Long hostname             - 30+ characters in the host
 +12  Port on unusual number    - any explicit port other than 80/443
 +12  Data or blob scheme       - "data:", "blob:", "javascript:"
 +10  HTTP instead of HTTPS     - traffic would not be encrypted
 +10  Many hyphens in hostname  - 3+ hyphens
 +10  Hostname looks like an IP - "192.168.ten.1" (number-only labels, dotted)
 +10  URL longer than 100 chars - obfuscation / tracking padding
 +10  Double URL encoding       - "%2520" style nested encoding
 +10  Suspicious host keywords  - "login-paypal.tld", "secure-bank.tld"
 + 8  Suspicious path keywords  - "/login", "/verify", "/account/update"
 + 8  Many query parameters     - 6+ parameters
 + 8  Obfuscated characters     - backslashes, encoded slashes, null bytes
 + 8  Phishing file hosting     - links on free cloud document services
 + 5  Shortener / redirector    - bit.ly, tinyurl, t.co, ...
 + 5  Embedded URL in query     - "?url=http://", "?redirect=..."
 + 5  Encoded characters in host

Thresholds
----------
 0  - 24  => Lower Risk
 25 - 49  => Suspicious
 50 - 100 => High Risk

Using and extending this module
-------------------------------
`analyze_url(raw)` returns an `AnalysisResult` dataclass. Add a new rule by
appending to the `findings` list inside `_collect_signals`; keep the message
short because the UI shows it directly.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Configuration / word lists
# ---------------------------------------------------------------------------

SUPPORTED_SCHEMES = ("http", "https")
MAAS_SCHEMES = {"data", "blob", "javascript"}

# Words that commonly appear in phishing hosts to create a false sense of trust.
SUSPICIOUS_HOST_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "password",
    "wallet", "support", "billing", "confirm", "recovery", "unlock", "bonus",
    "gift", "free", "prize", "claim", "otp", "kyc", "refund", "netbanking",
)

# Words that are normal in paths but appear in phishing landing pages.
# Not included on purpose: "account", "update", "secure" (too common in real
# URLs such as /account/settings), "cmd" (false positives on legitimate paths).
SUSPICIOUS_PATH_WORDS = (
    "login", "signin", "verify", "password", "wallet", "confirm",
    "recovery", "unlock", "claim", "otp", "kyc", "banking", "webscr",
    "session",
)

# Brands frequently abused in look-alike domains (substring match on hostname).
BRAND_NAMES = (
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "flipkart", "sbi", "icici", "hdfc", "axis",
    "phonepe", "paytm", "gpay", "statebank", "irctc", "linkedin", "dropbox",
    "adobe", "binance", "coinbase", "steam", "dhl", "fedex", "bankofamerica",
)

# "Registrable" domains for the brands above. If the hostname contains the
# brand but is NOT inside one of these, it is probably impersonating it.
BRAND_OFFICIAL_DOMAINS = {
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "google": ("google.com", "google.co.in", "gmail.com", "youtube.com"),
    "amazon": ("amazon.com", "amazon.in", "amazonaws.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "flipkart": ("flipkart.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "icici": ("icibank.com",),
    "hdfc": ("hdfcbank.com",),
    "axis": ("axisbank.com",),
    "phonepe": ("phonepe.com",),
    "paytm": ("paytm.com",),
    "statebank": ("sbi.co.in", "onlinesbi.sbi"),
    "irctc": ("irctc.co.in",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com",),
    "adobe": ("adobe.com",),
    "binance": ("binance.com",),
    "coinbase": ("coinbase.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "bankofamerica": ("bankofamerica.com",),
}

# Multi-part public suffixes so "co.uk" is not mistaken for a domain.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in",
    "ac.in", "gov.in", "nic.in", "co.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.mx", "co.za", "com.sg", "com.my", "co.ke",
}

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
    ".jar", ".apk", ".dmg", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".hta",
    ".ps1", ".sh", ".iso", ".img",
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "shorturl.at", "buff.ly", "rebrand.ly", "t.ly", "tiny.cc",
}

FREE_HOSTING_BAIT_WORDS = ("sharepoint", "onedrive", "docs.google", "drive.google")

# Thresholds -----------------------------------------------------------------
LONG_URL = 100
LONG_HOST = 30
EXCESSIVE_SUBDOMAINS = 4   # number of dots in a hostname (e.g. a.b.c.d.com)
UNUSUAL_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 8080, 8443}

# Risk labels ---------------------------------------------------------------
VERDICT_HIGH = "High Risk"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_LOW = "Lower Risk"
VERDICT_INVALID = "Invalid URL"

_HOST_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_ONLY_DIGITS_AND_DOTS = re.compile(r"^[0-9.]+$")
# Hexadecimal (0x7f000001) or large decimal (2130706433) host representations
_HEX_HOST = re.compile(r"^(?:0x[0-9a-f]+(?:\.[0-9a-f]+)*|[0-9]{7,})$", re.IGNORECASE)
_EMBEDDED_URL = re.compile(r"(?:https?%3a%2f%2f|https?://|www\.)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public result object
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One heuristic that fired, with its explanation and weight."""

    code: str
    title: str
    detail: str
    points: int
    severity: str = "medium"   # "high" | "medium" | "low" | "good" | "info"

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "points": self.points,
            "severity": self.severity,
        }


@dataclass
class AnalysisResult:
    """Everything the UI needs to display one scan."""

    input_url: str
    normalized_url: str
    score: int
    verdict: str
    findings: List[Finding] = field(default_factory=list)
    is_valid: bool = True
    error: Optional[str] = None
    hostname: str = ""
    scheme: str = ""

    @property
    def level_slug(self) -> str:
        """CSS suffix used by the templates: high / suspicious / low / invalid."""
        return classify(0 if not self.is_valid else self.score, valid=self.is_valid)

    @property
    def indicators(self) -> List[str]:
        """Legacy-friendly string list (kept for the old database format)."""
        return [f"{f.title} (+{f.points})" for f in self.findings]

    @property
    def recommendations(self) -> List[str]:
        return build_recommendations(self)

    def as_dict(self) -> dict:
        return {
            "input_url": self.input_url,
            "normalized_url": self.normalized_url,
            "score": self.score,
            "verdict": self.verdict,
            "is_valid": self.is_valid,
            "error": self.error,
            "hostname": self.hostname,
            "scheme": self.scheme,
            "findings": [f.as_dict() for f in self.findings],
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify(score: int, valid: bool = True) -> str:
    """Map a numeric score to a verdict slug (also used as a CSS class)."""
    if not valid:
        return "invalid"
    if score >= 50:
        return "high"
    if score >= 25:
        return "suspicious"
    return "low"


def score_to_verdict(score: int) -> str:
    """Map a numeric score to the human-readable verdict."""
    return {50: VERDICT_HIGH, 25: VERDICT_SUSPICIOUS, 0: VERDICT_LOW}[
        max((t for t in (50, 25, 0) if score >= t))
    ]


def _registered_domain(hostname: str) -> str:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) < 2:
        return hostname
    suffix2 = ".".join(parts[-2:])
    if suffix2 in TWO_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def _is_finding_safe(host: str, official: tuple) -> bool:
    """True when *host* is the brand's official domain or a subdomain of it."""
    for domain in official:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def _looks_like_ip_literal(hostname: str) -> bool:
    """Detect dotted numbers such as '192.168.ten.1' that ipaddress rejects."""
    if not _ONLY_DIGITS_AND_DOTS.match(hostname.replace(" ", "")):
        return False
    parts = hostname.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _normalize_hostname(hostname: str) -> str:
    """Lower-case, strip brackets/trailing dots and reject control characters."""
    return hostname.strip().strip("[]").rstrip(".").lower()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_url(raw_url: str) -> AnalysisResult:
    """Analyse a URL string using explainable heuristics. Never visits the URL."""
    original = raw_url if isinstance(raw_url, str) else ""
    original = original.strip()
    findings: List[Finding] = []

    def add(code, title, detail, points, severity="medium"):
        findings.append(Finding(code, title, detail, points, severity))

    def invalid(error: str, hint: str) -> AnalysisResult:
        add("invalid", "Invalid input", hint, 0, "info")
        return AnalysisResult(
            input_url=original,
            normalized_url=original,
            score=0,
            verdict=VERDICT_INVALID,
            findings=findings,
            is_valid=False,
            error=error,
        )

    # -- 0. Basic validation ------------------------------------------------
    if not original:
        return invalid("Please enter a URL.", "The URL field was empty.")

    if len(original) > 2048:
        return invalid(
            "That URL is too long to analyse.",
            "URLs longer than 2048 characters are rejected to keep the app fast.",
        )

    if any(ch in original for ch in ("\x00", "\r", "\n")) or any(ord(ch) < 32 for ch in original):
        return invalid(
            "The URL contains hidden control characters.",
            "Remove line breaks and control characters before scanning.",
        )

    # Add a scheme when the user typed "example.com/login".
    candidate = original if "://" in original else "https://" + original
    scheme_prefix = candidate.split("://", 1)[0].lower()

    if scheme_prefix in MAAS_SCHEMES:
        return invalid(
            f"The '{scheme_prefix}:' scheme is not scanned.",
            "PhishGuard only analyses http and https web addresses. Data, blob and "
            "javascript URLs can run code, so they are rejected for safety.",
        )

    try:
        parsed = urlparse(candidate)
        hostname = _normalize_hostname(parsed.hostname or "")
        port = parsed.port  # raises ValueError for "https://a.com:abc/"
    except ValueError:
        return invalid(
            "The URL could not be parsed.",
            "Check the address — an invalid port or malformed host was detected.",
        )

    if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
        return invalid(
            f"The '{parsed.scheme}:' scheme is not supported.",
            "Only http:// and https:// addresses can be analysed.",
        )

    if not hostname:
        return invalid(
            "The URL has no hostname.",
            "Example of a valid URL: https://example.com/login",
        )

    if hostname in ("localhost", "localhost.localdomain"):
        return invalid(
            "Local addresses are not scanned.",
            "localhost points to your own computer, not a website.",
        )

    # Bare IP addresses have no dots requirement below, so check first.
    is_hex_or_int_host = bool(_HEX_HOST.match(hostname))
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None

    if ip_obj is None:
        if len(hostname) > 253:
            return invalid("The hostname is too long.", "Hostnames cannot exceed 253 characters.")
        if not all(_HOST_LABEL_RE.match(label) for label in hostname.split(".")):
            return invalid(
                "The hostname contains invalid characters.",
                "Hostnames may only contain letters, digits, hyphens and dots.",
            )
        if "." not in hostname and not is_hex_or_int_host:
            return invalid(
                "The URL needs a full domain name.",
                "For example 'example.com' — single words like 'admin' are not web addresses.",
            )

    full_url = candidate

    # -- 1. Host and transport ---------------------------------------------
    if parsed.scheme.lower() == "http":
        add(
            "http", "No HTTPS encryption",
            "The address uses HTTP, so data sent to it could be read or modified in transit.",
            10, "medium",
        )

    if ip_obj is not None:
        add(
            "ip_host", "IP address instead of a domain",
            "Legitimate public websites normally use a domain name; raw IPs are common in phishing links.",
            25, "high",
        )
        if getattr(ip_obj, "is_private", False) or getattr(ip_obj, "is_loopback", False) \
                or getattr(ip_obj, "is_link_local", False):
            add("non_public_ip", "Private or reserved IP address",
                "This IP belongs to a private or special-use range and is not a normal public web host.",
                15, "high")

    network = candidate.split("://", 1)[-1]
    authority = network.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    if "@" in authority:
        # "https://www.paypal.com@10.0.0.1/login" — everything before @ is ignored by browsers.
        add(
            "userinfo", "Deceptive '@' in the URL",
            "Text before '@' is only a username. Browsers actually go to the host that follows it, "
            "which attackers use to fake a trusted name.",
            40, "high",
        )
        if ":" in authority.split("@", 1)[0]:
            add("credentials", "Embedded username and password",
                "The link carries credentials in plain text, a strong sign of a crafted phishing link.",
                20, "high")

    try:
        port_value = port
    except ValueError:  # pragma: no cover - already handled above
        port_value = None
    if port_value is not None and port_value not in (80, 443):
        add("port", f"Unusual port {port_value}",
            "Standard websites use ports 80 (HTTP) or 443 (HTTPS). Other ports are unusual.",
            12, "medium")

    # -- 2. Domain structure ------------------------------------------------
    if ip_obj is None and _looks_like_ip_literal(hostname):
        add("fake_ip", "Host looks like an IP address",
            "Every part of this host is a number. Numeric hosts are frequently used to hide the real domain.",
            10, "medium")

    if ip_obj is None and is_hex_or_int_host:
        add("hex_ip", "Hexadecimal or integer host",
            "Some browsers interpret values like 0x7f000001 or 2130706433 as an IP address.",
            30, "high")

    if any(label.startswith("xn--") for label in hostname.split(".")):
        add("punycode", "Punycode (internationalised) domain",
            "Punycode domains can look identical to well-known brands using different alphabet characters.",
            30, "high")

    dot_count = hostname.count(".")
    if ip_obj is None and dot_count >= EXCESSIVE_SUBDOMAINS:
        add("subdomains", f"Excessive subdomains ({dot_count + 1} labels)",
            "Many nested subdomains (e.g. secure.login.account.example.com) are used to push the real "
            "domain out of view on mobile screens.",
            15, "high")

    if len(hostname) > LONG_HOST:
        add("long_host", "Unusually long hostname",
            f"The hostname is {len(hostname)} characters long. Lengthy hosts often hide the true domain.",
            12, "medium")

    if hostname.count("-") >= 3:
        add("hyphens", "Many hyphens in the hostname",
            "Attackers register names such as 'secure-login-account-update.example.com' to look "
            "official.",
            10, "medium")

    registered = _registered_domain(hostname)
    if ip_obj is None:
        for brand in BRAND_NAMES:
            if brand in hostname and not _is_finding_safe(hostname, BRAND_OFFICIAL_DOMAINS.get(brand, ())):
                add("brand_lookalike", f"Possible '{brand}' impersonation",
                    f"The address mentions '{brand}' but is registered under '{registered}', not the "
                    f"brand's official domain.",
                    20, "high")
                break

        for token in SUSPICIOUS_HOST_WORDS:
            if token in hostname:
                add("host_keyword", f"Security keyword in the domain: '{token}'",
                    "Words like login/verify/secure in the hostname are frequently used to create a "
                    "false sense of trust.",
                    10, "medium")
                break

        if registered in SHORTENERS:
            add("shortener", "URL shortener",
                "Shortened links hide the real destination until the user clicks them.",
                5, "low")

        if any(hostname == h or hostname.endswith("." + h) for h in FREE_HOSTING_BAIT_WORDS):
            add("free_hosting", "Hosted on a public file-sharing service",
                "Phishing kits are often hosted on free cloud document services to borrow their reputation.",
                8, "medium")

    # -- 3. Full URL content ------------------------------------------------
    if len(full_url) > LONG_URL:
        add("long_url", "Long URL",
            f"The URL is {len(full_url)} characters long, which can hide the real destination "
            "in the address bar.",
            10, "medium")

    decoded_path = unquote(parsed.path or "")
    segments = [seg for seg in decoded_path.lower().split("/") if seg]
    tokens_in_path = [t for t in SUSPICIOUS_PATH_WORDS
                      if any(t in seg for seg in segments)]
    if tokens_in_path:
        token = tokens_in_path[0]
        add("path_keyword", f"Security keyword in the path: '{token}'",
            "Payment, login and account pages are the main targets of phishing kits.",
            8, "medium")

    if len(parsed.query) > 0:
        param_count = len([p for p in parsed.query.split("&") if p])
        if param_count >= 6:
            add("params", f"Many query parameters ({param_count})",
                "Long parameter lists are often used to inject victim data or disguises.",
                8, "medium")
        if _EMBEDDED_URL.search(parsed.query):
            add("embedded_url", "Another address embedded in the query",
                "Open-redirect style links (?url=http://evil.example) can send you somewhere unexpected.",
                5, "medium")

    lower_path = decoded_path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if lower_path.endswith(ext) or f"{ext}?" in lower_path:
            add("dangerous_file", f"Downloads a risky file type ({ext})",
                "Executables and Office/macro files are common malware delivery formats. Avoid "
                "opening them from unexpected links.",
                15, "high")
            break

    raw_lower = original.lower()
    if "%25" in raw_lower or re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", raw_lower):
        add("double_encoding", "Double-encoded characters",
            "Nested percent-encoding is normally used to bypass URL filters.",
            10, "medium")

    if "\\" in candidate:
        add("backslash", "Backslash in the URL",
            "Backslashes are not valid in web URLs and are used to confuse parsers "
            "(some browsers turn '\\' into '/').",
            8, "medium")

    if re.search(r"%(?:2f|5c|00)", raw_lower):
        add("encoded_slash", "Encoded slash or null byte",
            "Encoded '/' or NUL characters are a classic parser-confusion trick.",
            8, "medium")

    # -- 4. Positive signals (do not reduce the score) -----------------------
    if parsed.scheme.lower() == "https" and ip_obj is None:
        # Positive signals are informational only (0 points).
        add("https", "Uses HTTPS",
            "HTTPS encrypts your connection. Note that phishing sites can also use HTTPS, so a lock "
            "icon alone is not proof of safety.",
            0, "good")

    if hostname.startswith("www."):
        add("www", "Standard www subdomain",
            "The address begins with the common 'www.' prefix.",
            0, "good")

    # -- 5. Final score -------------------------------------------------------
    score = min(100, sum(f.points for f in findings))
    verdict = score_to_verdict(score)

    if not any(f.points > 0 for f in findings):
        add("clean", "No structural warning signs detected",
            "None of the heuristic rules fired. This does not prove the URL is safe — always verify "
            "the site through official channels.",
            0, "info")

    return AnalysisResult(
        input_url=original,
        normalized_url=full_url,
        score=score,
        verdict=verdict,
        findings=findings,
        is_valid=True,
        hostname=hostname,
        scheme=parsed.scheme.lower(),
    )


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

def build_recommendations(result: AnalysisResult) -> List[str]:
    """Return practical, beginner-friendly next steps for a scan result."""
    if not result.is_valid:
        return [
            "Check the spelling of the address. A valid link looks like https://example.com/page.",
            "Avoid pasting links from SMS, email or WhatsApp into tools unless you trust the sender.",
        ]

    codes = {f.code for f in result.findings}
    recs: List[str] = []

    if result.score >= 50:
        recs.append("Do not open this link or enter any details. Open the website by typing its "
                    "official address instead.")
        recs.append("If the link arrived by email or SMS, report it as phishing and then delete it.")
    elif result.score >= 25:
        recs.append("Verify the destination independently — visit the official website or contact "
                    "the organisation through a number you already know.")
        recs.append("Avoid entering passwords, OTPs or card details until you are certain.")
    else:
        recs.append("No strong structural warning was found, but still check the sender and the "
                    "site's HTTPS padlock before entering personal information.")
        recs.append("Bookmark trusted websites so you do not have to follow links from messages.")

    if "http" in codes:
        recs.append("Prefer the HTTPS version of this site and never type passwords on an HTTP page.")
    if "punycode" in codes:
        recs.append("Look closely at the letters in the domain — punycode names often mimic real brands "
                    "using look-alike characters.")
    if "userinfo" in codes or "credentials" in codes:
        recs.append("Ignore everything before the '@' — the real destination is the part immediately "
                    "after it.")
    if "ip_host" in codes:
        recs.append("Websites normally have domain names. Be especially cautious with links that use "
                    "a bare IP address.")
    if "brand_lookalike" in codes:
        recs.append("Reach the brand's site by typing its official address or through its verified "
                    "app, not through this link.")
    if "dangerous_file" in codes:
        recs.append("Do not download or open the file linked here. Scan any downloaded file with "
                    "your antivirus first.")
    if "shortener" in codes:
        recs.append("Expand the short link with a trusted link-preview service before clicking it.")

    recs.append("When in doubt, ask the organisation directly. Real companies never ask for "
                "passwords or OTPs by email.")
    # De-duplicate while keeping order.
    seen = set()
    unique = [r for r in recs if not (r in seen or seen.add(r))]
    return unique
