import re
import ipaddress
import hashlib

from difflib import SequenceMatcher
from email import policy
from email.parser import Parser
from html.parser import HTMLParser
from urllib.parse import urlparse


# =========================================================
# REGULAR EXPRESSIONS
# =========================================================

URL_RE = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.I,
)

HASH_RE = re.compile(
    r"\b[a-fA-F0-9]{64}\b|"
    r"\b[a-fA-F0-9]{40}\b|"
    r"\b[a-fA-F0-9]{32}\b"
)


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
}


URGENCY_TERMS = [
    "urgent",
    "immediately",
    "verify your account",
    "account suspended",
    "password expires",
    "action required",
    "unusual activity",
    "payment failed",
    "confirm your identity",
    "within 24 hours",
]


CREDENTIAL_TERMS = [
    "password",
    "login",
    "sign in",
    "credentials",
    "one-time passcode",
    "otp",
    "bank account",
    "credit card",
    "social security",
]


# =========================================================
# BRAND IMPERSONATION CONFIGURATION
# =========================================================

BRAND_DOMAINS = {
    "Microsoft": ["microsoft.com"],
    "Google": ["google.com"],
    "Amazon": ["amazon.com"],
    "Apple": ["apple.com"],
    "PayPal": ["paypal.com"],
}


# Common substitutions used in lookalike domains.
LOOKALIKE_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})


# =========================================================
# EMAIL PARSING
# =========================================================

def _decode_part(part):
    try:
        payload = part.get_content()

        if isinstance(payload, str):
            return payload

    except Exception:
        pass

    try:
        raw = part.get_payload(decode=True)

        if raw:
            return raw.decode(
                part.get_content_charset() or "utf-8",
                errors="replace",
            )

    except Exception:
        pass

    return ""


def parse_email(raw_email):
    msg = Parser(policy=policy.default).parsestr(raw_email)

    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():

            if part.get_content_maintype() == "multipart":
                continue

            if part.get_content_disposition() == "attachment":
                continue

            if part.get_content_type() in (
                "text/plain",
                "text/html",
            ):
                body_parts.append(_decode_part(part))

    else:
        body_parts.append(_decode_part(msg))

    body = "\n".join(body_parts)

    headers = {
        "subject": str(msg.get("subject", "")),
        "from": str(msg.get("from", "")),
        "to": str(msg.get("to", "")),
        "reply_to": str(msg.get("reply-to", "")),
        "return_path": str(msg.get("return-path", "")),
        "date": str(msg.get("date", "")),
        "message_id": str(msg.get("message-id", "")),
        "authentication_results": str(
            msg.get("authentication-results", "")
        ),
        "received_spf": str(msg.get("received-spf", "")),
    }

    return msg, headers, body


# =========================================================
# EMAIL AND URL UTILITIES
# =========================================================

def _addresses(value):
    return [
        address.lower()
        for address in EMAIL_RE.findall(value or "")
    ]


def _domain_from_email(address):
    if "@" not in address:
        return ""

    return address.rsplit("@", 1)[-1].strip(
        " >.,;"
    ).lower()


def _get_url_host(url):
    candidate = url.strip().rstrip(".,);!?]")

    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate

    try:
        return (urlparse(candidate).hostname or "").lower()

    except Exception:
        return ""


def _normalize_brand_text(value):
    return value.lower().translate(LOOKALIKE_TRANSLATION)


def _is_official_brand_domain(host, official_domains):
    """
    Match an official domain or its subdomain.

    For example:
    login.microsoft.com is a subdomain of microsoft.com.
    microsoft.com.attacker.example is NOT an official domain.
    """
    host = host.lower().rstrip(".")

    for domain in official_domains:
        domain = domain.lower()

        if host == domain or host.endswith("." + domain):
            return True

    return False


# =========================================================
# BRAND IMPERSONATION DETECTION
# =========================================================

def detect_brand_impersonation(sender, urls):
    """
    Detect possible brand impersonation in sender addresses
    and extracted URL domains.

    This uses local heuristics. It does not prove that a
    domain is malicious or verify domain ownership.
    """

    candidates = []

    # Analyze sender email domains.
    for address in _addresses(sender):
        domain = _domain_from_email(address)

        if domain:
            candidates.append({
                "source": "Sender",
                "domain": domain,
            })

    # Analyze URL destination domains.
    for url in urls:
        domain = _get_url_host(url)

        if domain:
            candidates.append({
                "source": "URL",
                "domain": domain,
            })

    findings = []
    seen = set()

    for candidate in candidates:
        domain = candidate["domain"]
        source = candidate["source"]

        # Avoid processing the same domain repeatedly.
        candidate_key = (domain, source)

        if candidate_key in seen:
            continue

        seen.add(candidate_key)

        # Skip IP addresses; other URL checks handle them.
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        # Inspect each configured brand.
        for brand, official_domains in BRAND_DOMAINS.items():

            # Genuine brand domains and their subdomains
            # should not trigger impersonation findings.
            if _is_official_brand_domain(
                domain,
                official_domains,
            ):
                continue

            normalized_domain = _normalize_brand_text(domain)
            labels = normalized_domain.split(".")

            matched = False
            reason = ""

            for official_domain in official_domains:
                brand_name = official_domain.split(".")[0]
                normalized_brand = _normalize_brand_text(
                    brand_name
                )

                for label in labels:

                    # Detect additional text appended to a
                    # brand name, such as microsoft-login.
                    if (
                        label.startswith(normalized_brand)
                        and label != normalized_brand
                    ):
                        matched = True
                        reason = (
                            "A domain label starts with the "
                            "brand name but contains additional "
                            "characters."
                        )
                        break

                    # Detect misspellings and lookalike labels.
                    similarity = SequenceMatcher(
                        None,
                        label,
                        normalized_brand,
                    ).ratio()

                    if (
                        label != normalized_brand
                        and len(label) >= 5
                        and similarity >= 0.78
                    ):
                        matched = True
                        reason = (
                            "A domain label closely resembles "
                            "the brand name."
                        )
                        break

                if matched:
                    break

            if matched:
                findings.append({
                    "brand": brand,
                    "domain": domain,
                    "source": source,
                    "reason": reason,
                    "official_domains": official_domains,
                })

                # Stop after the first matching brand for
                # this candidate to reduce duplicate findings.
                break

    return findings


# =========================================================
# HTML LINK ANALYSIS
# =========================================================

class EmailLinkParser(HTMLParser):

    def __init__(self):
        super().__init__()

        self.links = []
        self.current_href = None
        self.current_text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.current_href = dict(attrs).get("href")
            self.current_text = []

    def handle_data(self, data):
        if self.current_href is not None:
            self.current_text.append(data)

    def handle_endtag(self, tag):
        if (
            tag.lower() == "a"
            and self.current_href is not None
        ):
            self.links.append({
                "display_text": "".join(
                    self.current_text
                ).strip(),
                "destination": self.current_href.strip(),
            })

            self.current_href = None
            self.current_text = []


def analyze_html_links(html_body):
    parser = EmailLinkParser()

    try:
        parser.feed(html_body)

    except Exception:
        return []

    mismatches = []

    for link in parser.links:
        display = link["display_text"]
        destination = link["destination"]

        if not re.match(
            r"(?i)^(https?://|www\.)",
            display,
        ):
            continue

        display_host = _get_url_host(display)
        destination_host = _get_url_host(destination)

        if (
            display_host
            and destination_host
            and display_host != destination_host
        ):
            mismatches.append({
                "display_text": display,
                "destination": destination,
                "display_host": display_host,
                "destination_host": destination_host,
            })

    return mismatches


# =========================================================
# MAIN EMAIL ANALYZER
# =========================================================

def analyze_email(raw_email):
    msg, headers, body = parse_email(raw_email)

    combined = "\n".join([
        headers["subject"],
        headers["from"],
        headers["reply_to"],
        body,
    ])

    # Extract URLs.
    urls = sorted(set(
        url.rstrip(".,);!?]")
        for url in URL_RE.findall(combined)
    ))

    # Extract email addresses.
    emails = sorted(set(
        EMAIL_RE.findall(
            "\n".join(headers.values()) + "\n" + body
        )
    ))

    # Extract hash-like strings from the email body.
    hashes = sorted(set(HASH_RE.findall(body)))

    # Existing HTML mismatch detection.
    html_link_mismatches = analyze_html_links(body)

    # NEW FEATURE: Brand impersonation detection.
    brand_impersonation_hits = detect_brand_impersonation(
        headers["from"],
        urls,
    )

    findings = []
    score = 0

    def add(points, severity, title, detail):
        nonlocal score

        score += points

        findings.append({
            "points": points,
            "severity": severity,
            "title": title,
            "detail": detail,
        })

    # -----------------------------------------------------
    # 1. HTML LINK MISMATCH DETECTION
    # -----------------------------------------------------

    if html_link_mismatches:
        details = " | ".join(
            f"Displayed: {item['display_text']} -> "
            f"Destination: {item['destination']}"
            for item in html_link_mismatches
        )

        add(
            20,
            "High",
            "HTML link text and destination mismatch",
            details,
        )

    # -----------------------------------------------------
    # 2. SENDER AND REPLY-TO MISMATCH
    # -----------------------------------------------------

    sender_addresses = _addresses(headers["from"])
    reply_addresses = _addresses(headers["reply_to"])

    if sender_addresses and reply_addresses:
        sender_domain = _domain_from_email(
            sender_addresses[0]
        )

        reply_domain = _domain_from_email(
            reply_addresses[0]
        )

        if (
            sender_domain
            and reply_domain
            and sender_domain != reply_domain
        ):
            add(
                20,
                "High",
                "Sender / Reply-To domain mismatch",
                f"From domain is '{sender_domain}', but "
                f"Reply-To domain is '{reply_domain}'. "
                "This can be legitimate, but should be investigated.",
            )

    # -----------------------------------------------------
    # 3. EMAIL AUTHENTICATION RESULTS
    # -----------------------------------------------------

    auth = (
        headers["authentication_results"]
        + " "
        + headers["received_spf"]
    ).lower()

    auth_checks_found = False

    for mechanism in ("spf", "dkim", "dmarc"):
        matches = re.findall(
            r"\b"
            + mechanism
            + r"\s*=\s*"
            + r"(pass|fail|softfail|neutral|none|"
              r"temperror|permerror)\b",
            auth,
        )

        if matches:
            auth_checks_found = True
            result = matches[0]

            if result in ("fail", "softfail", "permerror"):
                add(
                    15,
                    "High",
                    f"{mechanism.upper()} authentication failure",
                    f"The supplied headers report "
                    f"{mechanism.upper()}={result}. "
                    "Validate against trusted mail-gateway logs.",
                )

    if not auth_checks_found:
        findings.append({
            "points": 0,
            "severity": "Info",
            "title": "Email authentication results unavailable",
            "detail": (
                "No parseable SPF/DKIM/DMARC result was found "
                "in the supplied headers. This is not proof "
                "of phishing."
            ),
        })

    # -----------------------------------------------------
    # 4. URGENCY LANGUAGE
    # -----------------------------------------------------

    lower_text = combined.lower()

    urgency_hits = sorted({
        term
        for term in URGENCY_TERMS
        if term in lower_text
    })

    if urgency_hits:
        add(
            min(15, 5 * len(urgency_hits)),
            "Medium",
            "Urgency or pressure language",
            "Matched terms: " + ", ".join(urgency_hits),
        )

    # -----------------------------------------------------
    # 5. CREDENTIAL AND SENSITIVE-DATA LANGUAGE
    # -----------------------------------------------------

    credential_hits = sorted({
        term
        for term in CREDENTIAL_TERMS
        if term in lower_text
    })

    if credential_hits:
        add(
            min(15, 5 * len(credential_hits)),
            "Medium",
            "Credential or sensitive-data language",
            "Matched terms: " + ", ".join(credential_hits),
        )

    # -----------------------------------------------------
    # 6. NEW: BRAND IMPERSONATION DETECTION
    # -----------------------------------------------------

    if brand_impersonation_hits:
        brand_details = []

        for hit in brand_impersonation_hits:
            brand_details.append(
                f"Brand: {hit['brand']} | "
                f"Source: {hit['source']} | "
                f"Domain: {hit['domain']} | "
                f"Reason: {hit['reason']} | "
                f"Expected official domain(s): "
                f"{', '.join(hit['official_domains'])}"
            )

        add(
            min(30, 15 * len(brand_impersonation_hits)),
            "High",
            "Possible brand impersonation",
            " | ".join(brand_details),
        )

    # -----------------------------------------------------
    # 7. SUSPICIOUS URL PATTERNS
    # -----------------------------------------------------

    suspicious_url_notes = []

    for url in urls:
        host = _get_url_host(url)

        if not host:
            continue

        host_l = host.lower()

        try:
            ipaddress.ip_address(host_l)

            suspicious_url_notes.append(
                f"{host}: URL uses a literal IP address"
            )

        except ValueError:
            pass

        if host_l in SHORTENERS:
            suspicious_url_notes.append(
                f"{host_l}: URL shortener obscures the destination"
            )

        if "xn--" in host_l:
            suspicious_url_notes.append(
                f"{host_l}: internationalized/punycode domain; "
                "inspect for lookalikes"
            )

        if "@" in url:
            suspicious_url_notes.append(
                f"{host_l}: URL contains an @ symbol, which can "
                "obscure the actual host"
            )

        if host_l.count("-") >= 3:
            suspicious_url_notes.append(
                f"{host_l}: domain contains several hyphens; "
                "inspect manually"
            )

    if suspicious_url_notes:
        add(
            min(25, 5 * len(suspicious_url_notes)),
            "High",
            "Potentially suspicious URL patterns",
            " | ".join(suspicious_url_notes),
        )

    # -----------------------------------------------------
    # 8. NO URL INFORMATION
    # -----------------------------------------------------

    if not urls:
        findings.append({
            "points": 0,
            "severity": "Info",
            "title": "No URLs detected",
            "detail": (
                "No obvious HTTP/HTTPS or www links were "
                "extracted from the provided text."
            ),
        })

    # -----------------------------------------------------
    # 9. FINAL RISK SCORE AND VERDICT
    # -----------------------------------------------------

    score = min(score, 100)

    if score >= 60:
        verdict = "Likely phishing — investigate"
        severity = "High"

    elif score >= 30:
        verdict = "Suspicious — manual review recommended"
        severity = "Medium"

    else:
        verdict = "Lower risk based on current rules"
        severity = "Low"

    # -----------------------------------------------------
    # 10. EVIDENCE HASH
    # -----------------------------------------------------

    evidence_hash = hashlib.sha256(
        raw_email.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()

    # -----------------------------------------------------
    # 11. RETURN ANALYSIS RESULTS
    # -----------------------------------------------------

    return {
        "headers": headers,
        "body_preview": body[:1200],
        "urls": urls,
        "html_link_mismatches": html_link_mismatches,
        "brand_impersonation_hits": brand_impersonation_hits,
        "email_addresses": emails,
        "hashes": hashes,
        "findings": findings,
        "risk_score": score,
        "verdict": verdict,
        "severity": severity,
        "evidence_sha256": evidence_hash,
        "disclaimer": (
            "Heuristic triage only. Brand similarity does not "
            "prove impersonation. Verify findings with trusted "
            "mail-gateway logs and threat-intelligence sources."
        ),
    }