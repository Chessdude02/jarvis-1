"""Network capability model and SSRF-safe URL validation.

Nothing in jarvis/tools/ calls this module yet -- there is no web-fetch
capability in this codebase (see THREAT_MODEL.md section 3). This exists
as pre-built, independently-tested infrastructure for when one lands, so
that feature starts from a validated SSRF defense instead of retrofitting
one after the fact. It has zero effect on anything today.

Two capability tiers, per the spec:
  NETWORK_READ  -- search the web, fetch a public page, read documentation.
                   Still requires this module's URL validation; never
                   implies NETWORK_WRITE.
  NETWORK_WRITE -- send email, submit a form, upload a file, post
                   somewhere, purchase something, modify an account. Must
                   always be its own, separately-approved capability --
                   this module doesn't grant it, only defines the tier.

is_safe_public_url() is the actual SSRF guard: validates scheme, rejects
credentials embedded in the URL, blocks the hostname pre-resolution AND
every IP it resolves to post-resolution (defending against DNS rebinding),
and covers the common numeric-IP-literal encodings (decimal, hex, octal)
used to smuggle a private address past a naive string check. Callers doing
their own HTTP fetch with redirect-following MUST call
revalidate_redirect() on every redirect target -- a URL that validates
initially can still redirect to an internal address.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class NetworkCapability(str, Enum):
    NETWORK_READ = "NETWORK_READ"
    NETWORK_WRITE = "NETWORK_WRITE"


_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Hostnames that are always blocked regardless of what they resolve to --
# catches the case where DNS resolution isn't even attempted by the caller
# for some reason, and blocks the "just say localhost" trivial case fast.
_BLOCKED_HOSTNAME_EXACT = frozenset({
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
})
_BLOCKED_HOSTNAME_SUFFIXES = (".localhost", ".local", ".internal", ".corp", ".home.arpa")

# Cloud metadata endpoints: these sit in the link-local range (caught by
# the IP-range check below too) but are named explicitly since they're the
# single highest-value SSRF target (instance credentials) and worth a
# belt-and-suspenders literal check independent of range math.
_BLOCKED_METADATA_HOSTS = frozenset({
    "169.254.169.254",  # AWS/Azure/GCP/OCI metadata
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",  # Alibaba Cloud metadata
})



@dataclass
class UrlValidationResult:
    safe: bool
    reason: str | None = None
    resolved_ips: tuple[str, ...] = ()


def _is_blocked_ip(ip_str: str) -> str | None:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"'{ip_str}' is not a valid IP address"
    if ip.is_loopback:
        return f"{ip_str} is a loopback address"
    if ip.is_private:
        return f"{ip_str} is a private-range address"
    if ip.is_link_local:
        return f"{ip_str} is a link-local address (this range includes cloud metadata endpoints)"
    if ip.is_reserved:
        return f"{ip_str} is in a reserved address range"
    if ip.is_multicast:
        return f"{ip_str} is a multicast address"
    if ip.is_unspecified:
        return f"{ip_str} is the unspecified address"
    if str(ip) in _BLOCKED_METADATA_HOSTS:
        return f"{ip_str} is a known cloud metadata endpoint"
    return None


def _decode_numeric_ip_literal(hostname: str) -> str | None:
    """Detects the legacy BSD inet_aton address forms used to smuggle a
    private address past a naive 'does this string look like an IP'
    check: a bare decimal/hex/octal 32-bit integer (2130706433,
    0x7f000001, 017700000001 are all 127.0.0.1), AND shorthand dotted
    forms with fewer than four parts where the last part absorbs the
    remaining bytes (127.1 == 127.0.0.1, 192.168.1 == 192.168.0.1) --
    including per-part mixed bases (0x7f.1). socket.inet_aton implements
    exactly this parsing (it's what a permissive resolver/HTTP client may
    do), so it's used here as the detector rather than reimplementing it.
    Returns the real dotted-quad form if hostname is one of these
    alternate encodings, else None (an ordinary 4-octet literal like
    "127.0.0.1", or an ordinary DNS name, isn't "encoded" in this sense).
    """
    try:
        ipaddress.IPv4Address(hostname)
        return None  # already a normal, unambiguous dotted-quad literal
    except ValueError:
        pass
    try:
        packed = socket.inet_aton(hostname)
    except OSError:
        return None
    return socket.inet_ntoa(packed)


def is_safe_public_url(url: str, *, resolve_dns: bool = True) -> UrlValidationResult:
    """The core SSRF check. resolve_dns=False is for unit testing only (no
    network access from this function during tests) -- real callers must
    leave it True so DNS-rebinding-style attacks are actually caught.
    """
    if not isinstance(url, str) or not url:
        return UrlValidationResult(False, "URL is empty or not a string")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return UrlValidationResult(False, f"URL could not be parsed: {exc}")

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return UrlValidationResult(False, f"Scheme '{parts.scheme}' is not allowed (only http/https)")

    if parts.username or parts.password:
        return UrlValidationResult(False, "URL embeds credentials; refusing to fetch")

    hostname = parts.hostname
    if not hostname:
        return UrlValidationResult(False, "URL has no hostname")
    hostname = hostname.lower().rstrip(".")

    if hostname in _BLOCKED_HOSTNAME_EXACT or hostname in _BLOCKED_METADATA_HOSTS:
        return UrlValidationResult(False, f"'{hostname}' is a blocked hostname")
    if any(hostname.endswith(suffix) for suffix in _BLOCKED_HOSTNAME_SUFFIXES):
        return UrlValidationResult(False, f"'{hostname}' matches a blocked internal-hostname suffix")

    # A bracketed literal IPv6 hostname, or a bare IPv4 literal, or a
    # numeric-encoded IPv4 literal -- check it directly without a DNS hop.
    literal = hostname
    numeric = _decode_numeric_ip_literal(hostname)
    if numeric:
        literal = numeric
    try:
        ipaddress.ip_address(literal)
        blocked = _is_blocked_ip(literal)
        if blocked:
            return UrlValidationResult(False, blocked, resolved_ips=(literal,))
        if numeric:
            # A DNS name would never look like "2130706433" -- something
            # went out of its way to encode an IP address numerically,
            # which is itself the pattern worth refusing even though this
            # particular address (rare) might be public.
            return UrlValidationResult(False, f"Hostname '{hostname}' is a numeric-encoded IP literal ({literal}); refusing as suspicious")
        return UrlValidationResult(True, resolved_ips=(literal,))
    except ValueError:
        pass  # not a literal IP -- an ordinary DNS name, fall through to resolution

    if not resolve_dns:
        return UrlValidationResult(True)

    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError) as exc:
        return UrlValidationResult(False, f"DNS resolution failed for '{hostname}': {exc}")

    resolved = tuple(sorted({info[4][0] for info in infos}))
    if not resolved:
        return UrlValidationResult(False, f"'{hostname}' resolved to no addresses")

    for ip_str in resolved:
        blocked = _is_blocked_ip(ip_str)
        if blocked:
            return UrlValidationResult(False, f"'{hostname}' resolves to {ip_str}: {blocked}", resolved_ips=resolved)

    return UrlValidationResult(True, resolved_ips=resolved)


def revalidate_redirect(redirect_url: str) -> UrlValidationResult:
    """Callers following HTTP redirects MUST call this on every hop's
    Location header before following it -- a URL that validated initially
    can still redirect to an internal address (classic SSRF-via-redirect),
    and DNS can legitimately answer differently between the first check and
    the actual connection (DNS rebinding). This is just is_safe_public_url
    under a name that makes the "call this again, every time" requirement
    explicit at call sites.
    """
    return is_safe_public_url(redirect_url, resolve_dns=True)
