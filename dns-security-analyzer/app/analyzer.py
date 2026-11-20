"""DNS, email-authentication and RDAP analysis helpers."""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import httpx

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1", "dkim", "mail", "smtp")


class LookupErrorBase(Exception):
    pass


def normalize_domain(value: str) -> str:
    """Accept a domain or URL, normalize IDNs, and reject malformed input."""
    raw = value.strip()
    if not raw:
        raise ValueError("Enter a domain name or IP address.")
    if "://" in raw:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
    else:
        host = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if host.count(":") == 1:
            hostname, port = host.rsplit(":", 1)
            if not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("If a port is included, it must be a number from 1 to 65535.")
            host = hostname
        elif ":" in host:
            raise ValueError("Enter a domain name, not an unbracketed IP address with a port.")
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain contains invalid international characters.") from exc
    if len(host) > 253 or "." not in host:
        raise ValueError("Enter a fully qualified domain such as example.com.")
    labels = host.split(".")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("The domain name contains an invalid label.")
    if labels[-1].isdigit():
        raise ValueError("The final domain label cannot be only numbers.")
    return host


def _resolver(server: str | None = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.5
    resolver.lifetime = 5
    if server:
        try:
            ip = ipaddress.ip_address(server)
        except ValueError as exc:
            raise ValueError("Custom DNS server must be an IPv4 or IPv6 address.") from exc
        if not ip.is_global:
            raise ValueError("Use a public DNS resolver address, not a private or reserved address.")
        resolver.nameservers = [str(ip)]
    return resolver


def query_records(name: str, types: list[str], server: str | None = None) -> dict[str, list[str]]:
    resolver = _resolver(server)
    output: dict[str, list[str]] = {}
    for record_type in types:
        try:
            answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
            output[record_type] = [item.to_text() for item in answer] if answer.rrset else []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            output[record_type] = []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException):
            output[record_type] = []
    return output


def reverse_lookup(address: str, server: str | None = None) -> dict[str, Any]:
    ip = ipaddress.ip_address(address)
    try:
        if server:
            ptr_name = ip.reverse_pointer
            records = query_records(ptr_name, ["PTR"], server)
            names = records["PTR"]
        else:
            names = [socket.gethostbyaddr(str(ip))[0]]
    except (socket.herror, socket.gaierror, OSError):
        names = []
    return {"target": str(ip), "reverse": names, "checked_at": datetime.now(timezone.utc).isoformat()}


def _txt_records(name: str, server: str | None = None) -> list[str]:
    return query_records(name, ["TXT"], server)["TXT"]


def _join_txt(value: str) -> str:
    # dnspython's TXT to_text() emits adjacent quoted chunks; preserve spaces inside chunks.
    return re.sub(r'"\s+"', "", value).strip('"').replace('\\"', '"')


def analyze_spf(records: list[str]) -> dict[str, Any]:
    matches = [r for r in records if _join_txt(r).lower().startswith("v=spf1")]
    if not matches:
        return {"status": "missing", "grade": "poor", "record": None,
                "finding": "No SPF record was found. This does not prove spoofing is possible, but SPF is not published here."}
    if len(matches) > 1:
        return {"status": "multiple", "grade": "review", "record": matches,
                "finding": "Multiple SPF records were found. A domain should publish one SPF policy; receivers may return PermError."}
    record = _join_txt(matches[0])
    tokens = record.lower().split()
    all_terms = [t for t in tokens if t.endswith("all")]
    terminal = all_terms[-1] if all_terms else ""
    if terminal == "-all":
        grade, status, finding = "good", "hard_fail", "The policy ends in -all, requesting receivers to fail unauthorized senders."
    elif terminal == "~all":
        grade, status, finding = "review", "soft_fail", "The policy ends in ~all, which is a soft-fail signal rather than a strict rejection."
    elif terminal in ("?all", "+all"):
        grade, status, finding = "poor", "permissive", "The policy is permissive and does not effectively restrict unlisted senders."
    else:
        grade, status, finding = "review", "no_all_mechanism", "No terminal all mechanism was identified. Review the policy manually."
    return {"status": status, "grade": grade, "record": record, "finding": finding}


def analyze_dmarc(records: list[str]) -> dict[str, Any]:
    matches = [r for r in records if _join_txt(r).lower().startswith("v=dmarc1")]
    if not matches:
        return {"status": "missing", "grade": "poor", "policy": None, "record": None,
                "finding": "No DMARC record was found at _dmarc. The domain's handling policy is not published there."}
    if len(matches) > 1:
        return {"status": "multiple", "grade": "review", "policy": None, "record": matches,
                "finding": "Multiple DMARC records were found. Publish a single valid DMARC record."}
    record = _join_txt(matches[0])
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.lower()] = value.strip()
    policy = tags.get("p", "none").lower()
    if policy == "reject":
        grade, finding = "good", "Policy is reject. Receivers are asked to reject mail that fails DMARC."
    elif policy == "quarantine":
        grade, finding = "good", "Policy is quarantine. Receivers are asked to treat failing mail as suspicious."
    elif policy == "none":
        grade, finding = "review", "Policy is none. This is monitoring mode and does not request quarantine or rejection."
    else:
        grade, finding = "poor", f"Unrecognized DMARC policy: {policy}. Review the record syntax."
    return {"status": "found", "grade": grade, "policy": policy, "record": record, "finding": finding,
            "alignment": {"aspf": tags.get("aspf", "r"), "adkim": tags.get("adkim", "r")},
            "pct": tags.get("pct", "100")}


def check_email_security(domain: str, server: str | None = None) -> dict[str, Any]:
    root_txt = _txt_records(domain, server)
    dmarc_txt = _txt_records(f"_dmarc.{domain}", server)
    dkim: dict[str, Any] = {}
    for selector in COMMON_DKIM_SELECTORS:
        records = _txt_records(f"{selector}._domainkey.{domain}", server)
        if records:
            dkim[selector] = [_join_txt(r) for r in records]
    return {
        "spf": analyze_spf(root_txt),
        "dmarc": analyze_dmarc(dmarc_txt),
        "dkim": {"checked_selectors": list(COMMON_DKIM_SELECTORS), "found": dkim,
                 "note": "DKIM selectors are not globally discoverable. Only common selectors were queried; no result does not prove DKIM is absent."},
    }


def _rdap_event(data: dict[str, Any], action: str) -> str | None:
    for event in data.get("events", []):
        if event.get("eventAction", "").lower() == action:
            return event.get("eventDate")
    return None


def _rdap_vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1:
        for item in vcard[1]:
            if len(item) > 3 and item[0] == "fn":
                return str(item[3])
    return None


def lookup_rdap(domain: str) -> dict[str, Any]:
    url = f"https://rdap.org/domain/{domain}"
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True, headers={"User-Agent": "DNS-Security-Analyzer/1.0"}) as client:
            response = client.get(url)
        if response.status_code == 404:
            return {"available": False, "note": "No RDAP registration record was returned."}
        response.raise_for_status()
        data = response.json()
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                registrar = _rdap_vcard_name(entity)
                if registrar:
                    break
        created = _rdap_event(data, "registration")
        age_days = None
        if created:
            try:
                born = datetime.fromisoformat(created.replace("Z", "+00:00")).date()
                age_days = (datetime.now(timezone.utc).date() - born).days
            except ValueError:
                pass
        return {
            "available": True,
            "registrar": registrar,
            "created": created,
            "updated": _rdap_event(data, "last changed"),
            "expires": _rdap_event(data, "expiration"),
            "age_days": age_days,
            "new_domain_warning": age_days is not None and 0 <= age_days < 90,
            "status": data.get("status", []),
            "nameservers": sorted({n.get("ldhName", "").lower() for n in data.get("nameservers", []) if n.get("ldhName")}),
            "note": "Registration data may be redacted or incomplete depending on the registry.",
        }
    except (httpx.HTTPError, ValueError):
        return {"available": False, "note": "RDAP data could not be retrieved right now."}


def analyze_domain(target: str, include_records: bool = True, include_email: bool = True,
                   include_rdap: bool = True, record_types: list[str] | None = None,
                   dns_server: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    selected = record_types or list(RECORD_TYPES)
    invalid = sorted(set(selected) - set(RECORD_TYPES))
    if invalid:
        raise ValueError(f"Unsupported DNS record type(s): {', '.join(invalid)}")
    # Always resolve A and AAAA. Use the same selected resolver for consistency.
    base = query_records(domain, ["A", "AAAA"], dns_server)
    result: dict[str, Any] = {
        "target": target,
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "ip_addresses": {"ipv4": base["A"], "ipv6": base["AAAA"]},
    }
    if include_records:
        requested = list(dict.fromkeys(selected))
        records = query_records(domain, requested, dns_server)
        result["dns_records"] = records
    if include_email:
        result["email_security"] = check_email_security(domain, dns_server)
    if include_rdap:
        result["registration"] = lookup_rdap(domain)
    result["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
    result["disclaimer"] = "Findings describe public DNS and registration data. They are not a malware verdict or proof that a domain is safe or malicious."
    return result
