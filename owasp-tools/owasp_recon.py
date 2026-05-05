#!/usr/bin/env python3
"""
OWASP Rekon Aman

Recon pasif dan pemeriksaan web aman untuk target yang sudah punya izin.
Tool ini tidak melakukan brute force, exploit, fuzzing agresif, atau mengirim payload.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any

import dns.resolver
import httpx
import tldextract
import whois
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape


APP_NAME = "OWASP Rekon Aman"
APP_AUTHOR = "NesiaBreach"
VERSION = "1.0.0"
DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = f"{APP_NAME}/{VERSION} rekon-aman-terotorisasi"
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

TECH_HINTS = {
    "server": {
        "nginx": "Nginx",
        "openresty": "OpenResty",
        "apache": "Apache",
        "cloudflare": "Cloudflare",
        "microsoft-iis": "Microsoft IIS",
        "litespeed": "LiteSpeed",
    },
    "headers": {
        "x-powered-by": "X-Powered-By",
        "x-generator": "X-Generator",
        "x-drupal-cache": "Drupal",
        "x-shopify-stage": "Shopify",
        "x-vercel-id": "Vercel",
        "x-nextjs-cache": "Next.js",
    },
    "html": {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "cdn.shopify.com": "Shopify",
        "__next": "Next.js",
        "nuxt": "Nuxt",
        "wixstatic": "Wix",
        "zyrosite": "Hostinger Website Builder",
        "webflow": "Webflow",
        "react": "React",
        "vue": "Vue.js",
    },
}

URL_LIKE_PARAM_NAMES = {
    "url",
    "uri",
    "u",
    "redirect",
    "redirect_uri",
    "return",
    "return_url",
    "next",
    "dest",
    "destination",
    "callback",
    "continue",
    "image",
    "file",
    "path",
    "proxy",
    "feed",
    "host",
}

INJECTION_LIKE_PARAM_NAMES = {
    "q",
    "s",
    "search",
    "query",
    "id",
    "user",
    "username",
    "email",
    "name",
    "page",
    "category",
    "filter",
    "sort",
    "order",
    "lang",
}


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    evidence: str
    recommendation: str


@dataclass
class ScanContext:
    target: str
    normalized_url: str
    host: str
    registered_domain: str
    started_at: str
    elapsed_seconds: float = 0
    in_scope: bool = False
    scope_notes: list[str] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    robots: dict[str, Any] = field(default_factory=dict)
    sitemap: dict[str, Any] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    params: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    exposed_files: list[dict[str, Any]] = field(default_factory=list)
    owasp: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target kosong")
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme:
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Hanya target http dan https yang didukung")
    if not parsed.netloc:
        raise ValueError("Target harus berisi domain atau host")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def hostname_from_url(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    if not host:
        raise ValueError("Could not parse hostname")
    return host.lower().rstrip(".")


def registered_domain(host: str) -> str:
    ext = TLD_EXTRACTOR(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def load_scope(scope_file: str | None) -> list[str]:
    if not scope_file:
        return []
    path = Path(scope_file)
    if not path.exists():
        raise FileNotFoundError(f"File scope tidak ditemukan: {scope_file}")
    items: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(line.lower())
    return items


def is_scope_match(host: str, allowed: list[str]) -> tuple[bool, list[str]]:
    if not allowed:
        return True, ["File scope tidak diberikan. Target dianggap sudah diizinkan oleh pengguna."]
    notes = []
    for item in allowed:
        clean = item.replace("https://", "").replace("http://", "").split("/")[0].lower()
        if clean.startswith("*."):
            suffix = clean[1:]
            if host.endswith(suffix):
                return True, [f"Cocok dengan wildcard scope {item}"]
        elif host == clean or host.endswith("." + clean):
            return True, [f"Cocok dengan scope {item}"]
        else:
            notes.append(f"Tidak cocok dengan {item}")
    return False, notes


def safe_get(client: httpx.Client, url: str, errors: list[str]) -> httpx.Response | None:
    try:
        return client.get(url)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"GET {url}: {exc}")
        return None


def dns_lookup(host: str, errors: list[str]) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA"]:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=DEFAULT_TIMEOUT)
            values = []
            for answer in answers:
                if rtype == "MX":
                    values.append(f"{answer.preference} {answer.exchange}".rstrip("."))
                elif rtype == "TXT":
                    values.append(" ".join(part.decode("utf-8", "replace") for part in answer.strings))
                else:
                    values.append(str(answer).rstrip("."))
            records[rtype] = sorted(set(values))
        except Exception as exc:  # noqa: BLE001
            records[rtype] = []
            if rtype in {"A", "AAAA"}:
                errors.append(f"Lookup DNS {rtype} gagal: {exc}")
    return records


def whois_lookup(domain: str, errors: list[str]) -> dict[str, Any]:
    try:
        raw = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Lookup WHOIS gagal: {exc}")
        return {}

    result: dict[str, Any] = {}
    for key in ["domain_name", "registrar", "creation_date", "expiration_date", "updated_date", "name_servers", "status", "emails"]:
        value = getattr(raw, key, None)
        result[key] = make_json_safe(value)
    return result


def make_json_safe(value: Any) -> Any:
    if is_dataclass(value):
        return make_json_safe(asdict(value))
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [make_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(make_json_safe(item) for item in value)
    if isinstance(value, dict):
        return {str(key): make_json_safe(val) for key, val in value.items()}
    return value


def fetch_http_summary(client: httpx.Client, url: str, errors: list[str]) -> tuple[dict[str, Any], str]:
    response = safe_get(client, url, errors)
    if response is None:
        return {}, ""
    history = [
        {
            "status_code": item.status_code,
            "url": str(item.url),
            "location": item.headers.get("location", ""),
        }
        for item in response.history
    ]
    headers = {key.lower(): value for key, value in response.headers.items()}
    summary = {
        "url": str(response.url),
        "status_code": response.status_code,
        "reason": response.reason_phrase,
        "history": history,
        "headers": headers,
        "server": response.headers.get("server", ""),
        "content_type": response.headers.get("content-type", ""),
        "content_length": response.headers.get("content-length", ""),
    }
    return summary, response.text[:500_000]


def check_security_headers(headers: dict[str, str], findings: list[Finding]) -> dict[str, Any]:
    present = {}
    missing = []
    for header, label in SECURITY_HEADERS.items():
        value = headers.get(header)
        present[label] = value or ""
        if not value:
            missing.append(label)

    important_missing = [name for name in missing if name in {"HSTS", "Content-Security-Policy", "X-Content-Type-Options"}]
    if important_missing:
        findings.append(
            Finding(
                title="Header keamanan penting belum ada",
                severity="Low",
                category="A05 Kesalahan Konfigurasi Keamanan",
                evidence=", ".join(important_missing),
                recommendation="Tambahkan header keamanan yang sesuai setelah uji kompatibilitas, terutama HSTS, CSP, dan X-Content-Type-Options.",
            )
        )
    return {"present": present, "missing": missing}


def get_tls_info(host: str, port: int, findings: list[Finding], errors: list[str]) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info = {
                    "version": ssock.version(),
                    "cipher": ssock.cipher(),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_names": [item[1] for item in cert.get("subjectAltName", []) if item[0].lower() == "dns"],
                }
                not_after = cert.get("notAfter")
                if not_after:
                    expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
                    days_left = (expires - dt.datetime.now(dt.timezone.utc)).days
                    info["days_until_expiry"] = days_left
                    if days_left < 30:
                        findings.append(
                            Finding(
                                title="Sertifikat TLS hampir kedaluwarsa",
                                severity="Medium" if days_left < 7 else "Low",
                                category="A02 Kegagalan Kriptografi",
                                evidence=f"Sertifikat kedaluwarsa dalam {days_left} hari",
                                recommendation="Perbarui sertifikat dan pastikan pembaruan otomatis berjalan.",
                            )
                        )
                return info
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Pemeriksaan TLS gagal: {exc}")
        return {}


def parse_robots(client: httpx.Client, base_url: str, errors: list[str]) -> dict[str, Any]:
    url = urllib.parse.urljoin(base_url, "/robots.txt")
    response = safe_get(client, url, errors)
    if response is None:
        return {"url": url, "status_code": None, "directives": []}
    directives = []
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            directives.append({"key": key.strip(), "value": value.strip()})
    return {"url": url, "status_code": response.status_code, "directives": directives[:100]}


def parse_sitemap(client: httpx.Client, base_url: str, limit: int, errors: list[str]) -> dict[str, Any]:
    url = urllib.parse.urljoin(base_url, "/sitemap.xml")
    response = safe_get(client, url, errors)
    if response is None:
        return {"url": url, "status_code": None, "urls": []}
    urls: list[str] = []
    soup = BeautifulSoup(response.text, "xml")
    for loc in soup.find_all("loc"):
        text = loc.get_text(strip=True)
        if text:
            urls.append(text)
        if len(urls) >= limit:
            break
    return {"url": url, "status_code": response.status_code, "urls": urls, "count_returned": len(urls)}


def check_exposed_files(client: httpx.Client, base_url: str, errors: list[str]) -> list[dict[str, Any]]:
    paths = [
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml",
        "/humans.txt",
        "/ads.txt",
        "/app-ads.txt",
        "/manifest.json",
        "/.well-known/change-password",
    ]
    results = []
    for path in paths:
        url = urllib.parse.urljoin(base_url, path)
        response = safe_get(client, url, errors)
        if response is None:
            continue
        interesting = response.status_code in {200, 204, 301, 302, 307, 308}
        results.append(
            {
                "path": path,
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "interesting": interesting,
            }
        )
    return results


def analyze_cookies(headers: dict[str, str], findings: list[Finding]) -> list[dict[str, Any]]:
    raw = headers.get("set-cookie")
    if not raw:
        return []

    cookies = []
    cookie_parts = split_set_cookie_header(raw)
    for item in cookie_parts:
        first = item.split(";", 1)[0]
        name = first.split("=", 1)[0].strip()
        lowered = item.lower()
        cookie = {
            "name": name,
            "secure": "secure" in lowered,
            "httponly": "httponly" in lowered,
            "samesite": "samesite=" in lowered,
        }
        cookies.append(cookie)
        missing = [flag for flag in ["secure", "httponly", "samesite"] if not cookie[flag]]
        if missing:
            findings.append(
                Finding(
                    title=f"Cookie belum memakai flag yang disarankan: {name}",
                    severity="Low",
                    category="A02 Kegagalan Kriptografi",
                    evidence=f"Belum ada: {', '.join(missing)}",
                    recommendation="Aktifkan Secure, HttpOnly, dan SameSite jika kompatibel dengan alur aplikasi.",
                )
            )
    return cookies


def split_set_cookie_header(raw: str) -> list[str]:
    parts = []
    current = []
    in_expires = False
    for token in raw.split(","):
        lowered = token.lower()
        if "expires=" in lowered:
            in_expires = True
            current.append(token)
            continue
        if in_expires and (";" in token):
            in_expires = False
            current.append(token)
            continue
        if "=" in token.split(";", 1)[0] and current:
            parts.append(",".join(current).strip())
            current = [token]
        else:
            current.append(token)
    if current:
        parts.append(",".join(current).strip())
    return parts


def analyze_html(url: str, html: str, findings: list[Finding]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            inputs.append(
                {
                    "tag": field.name,
                    "name": field.get("name", ""),
                    "type": field.get("type", ""),
                    "id": field.get("id", ""),
                }
            )
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        forms.append({"method": method, "action": urllib.parse.urljoin(url, action), "inputs": inputs})

    params = []
    parsed = urllib.parse.urlparse(url)
    for key in urllib.parse.parse_qs(parsed.query):
        params.append(classify_param(str(url), key, "current_url"))
    for link in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(url, link["href"])
        parsed_link = urllib.parse.urlparse(href)
        for key in urllib.parse.parse_qs(parsed_link.query):
            params.append(classify_param(href, key, "link"))

    if forms:
        findings.append(
            Finding(
                title="Form terdeteksi untuk review manual",
                severity="Info",
                category="A03 Injection",
                evidence=f"{len(forms)} form ditemukan. Tidak ada payload yang dikirim.",
                recommendation="Validasi manual penanganan input sisi server, proteksi CSRF, dan logika otorisasi.",
            )
        )

    technologies = fingerprint_technologies(soup, html)
    return forms[:50], dedupe_params(params)[:150], technologies


def classify_param(url: str, name: str, source: str) -> dict[str, Any]:
    lowered = name.lower()
    categories = []
    if lowered in URL_LIKE_PARAM_NAMES or any(word in lowered for word in ["url", "uri", "redirect", "callback", "next"]):
        categories.append("Parameter mirip URL; review risiko open redirect atau SSRF")
    if lowered in INJECTION_LIKE_PARAM_NAMES:
        categories.append("Parameter mirip input; review penanganan injection")
    if not categories:
        categories.append("Parameter umum")
    return {"name": name, "source": source, "url": url, "notes": categories}


def dedupe_params(params: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in params:
        key = (item["name"], item["source"], item["url"])
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def fingerprint_technologies(soup: BeautifulSoup, html: str) -> list[str]:
    found = set()
    lowered_html = html.lower()
    for marker, tech in TECH_HINTS["html"].items():
        if marker.lower() in lowered_html:
            found.add(tech)
    generator = soup.find("meta", attrs={"name": lambda value: value and value.lower() == "generator"})
    if generator and generator.get("content"):
        found.add(f"Generator: {generator['content']}")
    for script in soup.find_all("script", src=True):
        src = script["src"].lower()
        if "jquery" in src:
            found.add("jQuery")
        if "bootstrap" in src:
            found.add("Bootstrap")
        if "react" in src:
            found.add("React")
    return sorted(found)


def fingerprint_from_headers(headers: dict[str, str]) -> list[str]:
    found = set()
    server = headers.get("server", "").lower()
    for marker, tech in TECH_HINTS["server"].items():
        if marker in server:
            found.add(tech)
    for header, label in TECH_HINTS["headers"].items():
        if headers.get(header):
            found.add(f"{label}: {headers[header]}")
    return sorted(found)


def build_owasp_mapping(ctx: ScanContext) -> list[dict[str, Any]]:
    has_hsts = bool(ctx.http.get("security_headers", {}).get("present", {}).get("HSTS"))
    has_csp = bool(ctx.http.get("security_headers", {}).get("present", {}).get("Content-Security-Policy"))
    url_like = [p for p in ctx.params if any("URL-like" in note for note in p.get("notes", []))]
    input_like = [p for p in ctx.params if any("Input-like" in note for note in p.get("notes", []))]
    login_forms = [
        form for form in ctx.forms
        if any((field.get("type") or "").lower() == "password" for field in form.get("inputs", []))
    ]

    return [
        {
            "id": "A01",
            "name": "Broken Access Control",
            "status": "Perlu validasi manual",
            "evidence": "Recon aman otomatis tidak bisa membuktikan kelemahan otorisasi.",
            "safe_next_step": "Review role yang sudah login, object ID, rute admin, dan pengecekan otorisasi sisi server.",
        },
        {
            "id": "A02",
            "name": "Kegagalan Kriptografi",
            "status": "Pemeriksaan selesai",
            "evidence": f"HSTS: {'ada' if has_hsts else 'belum ada'}, TLS: {ctx.tls.get('version', 'tidak diketahui')}, cookie direview: {len(ctx.cookies)}",
            "safe_next_step": "Pastikan alur HTTPS-only, cookie Secure, kebijakan HSTS, dan pembaruan sertifikat.",
        },
        {
            "id": "A03",
            "name": "Injection",
            "status": "Hanya indikator pasif",
            "evidence": f"Form: {len(ctx.forms)}, parameter mirip input: {len(input_like)}. Tidak ada payload yang dikirim.",
            "safe_next_step": "Uji validasi input secara manual di environment yang terotorisasi.",
        },
        {
            "id": "A04",
            "name": "Desain Tidak Aman",
            "status": "Perlu validasi manual",
            "evidence": "Kelemahan desain perlu review alur bisnis.",
            "safe_next_step": "Threat-model alur penting: signup, pembayaran, upload, reset password, dan approval workflow.",
        },
        {
            "id": "A05",
            "name": "Kesalahan Konfigurasi Keamanan",
            "status": "Pemeriksaan selesai",
            "evidence": f"Header belum ada: {', '.join(ctx.http.get('security_headers', {}).get('missing', [])) or 'tidak ada yang terdeteksi'}",
            "safe_next_step": "Perbaiki header yang belum ada, hilangkan error verbose, dan batasi file publik yang tidak perlu.",
        },
        {
            "id": "A06",
            "name": "Komponen Rentan dan Usang",
            "status": "Hanya fingerprint",
            "evidence": f"Teknologi terdeteksi: {', '.join(ctx.technologies) or 'tidak ada fingerprint'}",
            "safe_next_step": "Bandingkan versi yang sudah dikonfirmasi dengan advisory vendor dan kebijakan patch.",
        },
        {
            "id": "A07",
            "name": "Kegagalan Identifikasi dan Autentikasi",
            "status": "Hanya indikator pasif",
            "evidence": f"Form password ditemukan: {len(login_forms)}. Tidak ada percobaan login.",
            "safe_next_step": "Review MFA, kebijakan password, lockout/rate limit, rotasi session, dan alur reset.",
        },
        {
            "id": "A08",
            "name": "Kegagalan Integritas Software dan Data",
            "status": "Indikasi header dan asset",
            "evidence": f"CSP: {'ada' if has_csp else 'belum ada'}, teknologi: {len(ctx.technologies)}",
            "safe_next_step": "Review integritas dependency, SRI untuk script pihak ketiga, kontrol CI/CD, dan rilis bertanda tangan.",
        },
        {
            "id": "A09",
            "name": "Kegagalan Logging dan Monitoring Keamanan",
            "status": "Perlu validasi manual",
            "evidence": "Recon eksternal tidak bisa memastikan cakupan logging internal.",
            "safe_next_step": "Validasi audit log untuk event auth, aksi admin, error, alert, dan handoff incident response.",
        },
        {
            "id": "A10",
            "name": "Server-Side Request Forgery",
            "status": "Hanya indikator pasif",
            "evidence": f"Parameter mirip URL ditemukan: {len(url_like)}. Tidak ada request SSRF.",
            "safe_next_step": "Review manual fitur yang mengambil URL dan terapkan allowlist, kontrol egress jaringan, serta blok IP metadata.",
        },
    ]


def add_risk_findings(ctx: ScanContext) -> None:
    for param in ctx.params:
        if any("URL-like" in note for note in param.get("notes", [])):
            ctx.findings.append(
                Finding(
                    title=f"Parameter mirip URL terdeteksi: {param['name']}",
                    severity="Info",
                    category="A10 Review SSRF / Open Redirect",
                    evidence=param["url"],
                    recommendation="Review apakah parameter ini bisa memicu fetch sisi server atau redirect. Jangan uji SSRF tanpa izin eksplisit.",
                )
            )

    if ctx.http.get("status_code", 0) >= 500:
        ctx.findings.append(
            Finding(
                title="Server error teramati",
                severity="Low",
                category="A05 Kesalahan Konfigurasi Keamanan",
                evidence=f"HTTP {ctx.http.get('status_code')}",
                recommendation="Review log server dan pastikan halaman error production tidak membocorkan stack trace atau detail sensitif.",
            )
        )


def run_scan(args: argparse.Namespace) -> ScanContext:
    started = time.time()
    normalized = normalize_target(args.target)
    host = hostname_from_url(normalized)
    reg_domain = registered_domain(host)
    ctx = ScanContext(
        target=args.target,
        normalized_url=normalized,
        host=host,
        registered_domain=reg_domain,
        started_at=dt.datetime.now(dt.timezone.utc).isoformat(),
    )

    allowed = load_scope(args.scope_file)
    ctx.in_scope, ctx.scope_notes = is_scope_match(host, allowed)
    if not ctx.in_scope:
        ctx.errors.append("Target berada di luar file scope yang diberikan. Scan dihentikan.")
        return ctx

    timeout = httpx.Timeout(args.timeout)
    headers = {"User-Agent": args.user_agent}
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=True, verify=not args.insecure) as client:
        ctx.dns = dns_lookup(host, ctx.errors)
        if not args.skip_whois:
            ctx.whois = whois_lookup(reg_domain, ctx.errors)

        ctx.http, html = fetch_http_summary(client, normalized, ctx.errors)
        response_headers = ctx.http.get("headers", {})
        if response_headers:
            ctx.http["security_headers"] = check_security_headers(response_headers, ctx.findings)
            ctx.cookies = analyze_cookies(response_headers, ctx.findings)
        else:
            ctx.http["security_headers"] = {"present": {}, "missing": []}

        if urllib.parse.urlparse(normalized).scheme == "https":
            ctx.tls = get_tls_info(host, 443, ctx.findings, ctx.errors)

        ctx.robots = parse_robots(client, normalized, ctx.errors)
        ctx.sitemap = parse_sitemap(client, normalized, args.sitemap_limit, ctx.errors)
        ctx.exposed_files = check_exposed_files(client, normalized, ctx.errors)
        ctx.forms, ctx.params, html_tech = analyze_html(ctx.http.get("url", normalized), html, ctx.findings)
        header_tech = fingerprint_from_headers(response_headers)
        ctx.technologies = sorted(set(html_tech + header_tech))

    add_risk_findings(ctx)
    ctx.owasp = build_owasp_mapping(ctx)
    ctx.elapsed_seconds = round(time.time() - started, 2)
    return ctx


def write_json(ctx: ScanContext, path: str) -> None:
    data = make_json_safe(ctx)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html(ctx: ScanContext, path: str) -> None:
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(ctx=ctx, app_name=APP_NAME, version=VERSION, author=APP_AUTHOR)
    Path(path).write_text(html, encoding="utf-8")


def severity_score(severity: str) -> int:
    return {"High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(severity, 0)


def print_summary(ctx: ScanContext) -> None:
    print(f"{APP_NAME} v{VERSION}")
    print(f"Dibuat oleh: {APP_AUTHOR}")
    print(f"Target: {ctx.normalized_url}")
    print(f"Masuk scope: {ctx.in_scope}")
    if ctx.http:
        print(f"HTTP: {ctx.http.get('status_code')} {ctx.http.get('reason')} -> {ctx.http.get('url')}")
    print(f"DNS A: {', '.join(ctx.dns.get('A', [])) or '-'}")
    print(f"Teknologi: {', '.join(ctx.technologies) or '-'}")
    print(f"Temuan: {len(ctx.findings)}")
    for finding in sorted(ctx.findings, key=lambda item: severity_score(item.severity), reverse=True):
        print(f"- [{finding.severity}] {finding.title} ({finding.category})")
    if ctx.errors:
        print(f"Error/peringatan: {len(ctx.errors)}")
        for error in ctx.errors[:8]:
            print(f"- {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owasp_recon.py",
        description="Recon aman OWASP Top 10 dan pembuatan report untuk target terotorisasi.",
    )
    parser.add_argument("target", help="URL atau domain target, contoh https://example.com")
    parser.add_argument("--out", default="report.html", help="Path report HTML. Default: report.html")
    parser.add_argument("--json-out", default="report.json", help="Path report JSON. Default: report.json")
    parser.add_argument("--scope-file", help="File opsional berisi domain yang diizinkan, satu per baris. Mendukung *.example.com")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout HTTP dalam detik. Default: 10")
    parser.add_argument("--sitemap-limit", type=int, default=100, help="Maksimum URL sitemap yang dimasukkan. Default: 100")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent kustom")
    parser.add_argument("--skip-whois", action="store_true", help="Lewati lookup WHOIS")
    parser.add_argument("--insecure", action="store_true", help="Nonaktifkan verifikasi sertifikat TLS untuk request HTTP")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        ctx = run_scan(args)
        write_json(ctx, args.json_out)
        write_html(ctx, args.out)
        print_summary(ctx)
        print(f"Report HTML: {Path(args.out).resolve()}")
        print(f"Report JSON: {Path(args.json_out).resolve()}")
        return 0 if ctx.in_scope else 2
    except KeyboardInterrupt:
        print("Dihentikan.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
