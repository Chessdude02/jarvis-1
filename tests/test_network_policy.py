"""SSRF-safe URL validation. Not wired to any tool yet (no web-fetch
capability exists in this codebase), but fully testable in isolation --
see jarvis/security/network_policy.py's module docstring and
THREAT_MODEL.md section 3 for why this is pre-built ahead of that feature.

resolve_dns=False is used throughout so these tests never touch the
network; a handful of dedicated tests at the bottom exercise real DNS
resolution against example.com and a guaranteed-invalid domain.
"""
from __future__ import annotations

from jarvis.security.network_policy import is_safe_public_url, revalidate_redirect


def _blocked(url: str) -> bool:
    return not is_safe_public_url(url, resolve_dns=False).safe


def _allowed(url: str) -> bool:
    return is_safe_public_url(url, resolve_dns=False).safe


# -- loopback / private / link-local -----------------------------------------

def test_localhost_hostname_blocked():
    assert _blocked("http://localhost/admin")


def test_loopback_ipv4_blocked():
    assert _blocked("http://127.0.0.1/admin")
    assert _blocked("http://127.255.255.255/")


def test_loopback_ipv6_blocked():
    assert _blocked("http://[::1]/admin")


def test_private_ranges_blocked():
    assert _blocked("http://10.0.0.5/")
    assert _blocked("http://172.16.0.1/")
    assert _blocked("http://172.31.255.255/")
    assert _blocked("http://192.168.1.1/")


def test_link_local_blocked():
    assert _blocked("http://169.254.1.1/")


def test_unspecified_address_blocked():
    assert _blocked("http://0.0.0.0/")


def test_cgnat_shared_address_space_blocked():
    # 100.64.0.0/10 (RFC 6598) -- Python's ipaddress.is_private is False for
    # this range (a known upstream gap), but it's non-internet-routable and
    # used internally by ISPs/cloud providers; the Alibaba metadata host
    # (100.100.100.200, special-cased separately below) sits inside it.
    # Found by testing: this range sailed through before the is_global
    # catch-all was added.
    assert _blocked("http://100.64.0.1/")
    assert _blocked("http://100.100.100.100/")
    assert _blocked("http://100.127.255.255/")


def test_ietf_benchmarking_and_documentation_ranges_blocked():
    assert _blocked("http://198.18.0.1/")  # RFC 2544 benchmarking
    assert _blocked("http://192.0.2.1/")  # TEST-NET-1 documentation
    assert _blocked("http://203.0.113.1/")  # TEST-NET-3 documentation


# -- cloud metadata endpoints -------------------------------------------------

def test_aws_azure_gcp_metadata_ip_blocked():
    assert _blocked("http://169.254.169.254/latest/meta-data/")


def test_gcp_metadata_hostname_blocked():
    assert _blocked("http://metadata.google.internal/computeMetadata/v1/")


def test_alibaba_metadata_blocked():
    assert _blocked("http://100.100.100.200/latest/meta-data/")


# -- numeric IP literal encodings (SSRF bypass tricks) -----------------------

def test_decimal_encoded_loopback_blocked():
    assert _blocked("http://2130706433/")  # 127.0.0.1


def test_hex_encoded_loopback_blocked():
    assert _blocked("http://0x7f000001/")  # 127.0.0.1


def test_octal_encoded_loopback_blocked():
    assert _blocked("http://017700000001/")  # 127.0.0.1


def test_shorthand_dotted_loopback_blocked():
    # Legacy BSD inet_aton shorthand: fewer than 4 octets, last one
    # absorbs the remaining bytes. Real HTTP clients/resolvers do parse
    # this. This form specifically evaded an earlier version of this
    # module's implementation (found by testing) before switching to
    # socket.inet_aton as the detector.
    assert _blocked("http://127.1/admin")
    assert _blocked("http://127.0.1/admin")


def test_shorthand_dotted_private_range_blocked():
    assert _blocked("http://192.168.1/x")  # == 192.168.0.1
    assert _blocked("http://10.1/x")  # == 10.0.0.1


def test_mixed_base_encoded_loopback_blocked():
    assert _blocked("http://0x7f.1/")  # hex first octet, decimal shorthand rest


# -- scheme / credential restrictions -----------------------------------------

def test_non_http_schemes_blocked():
    assert _blocked("file:///etc/passwd")
    assert _blocked("ftp://internal.server/")
    assert _blocked("gopher://internal.server/")
    assert _blocked("data:text/plain;base64,SGVsbG8=")


def test_embedded_credentials_blocked():
    assert _blocked("http://user:pass@evil.example.com/")


def test_empty_or_non_string_url_blocked():
    assert _blocked("")
    assert not is_safe_public_url(None, resolve_dns=False).safe
    assert not is_safe_public_url(12345, resolve_dns=False).safe


# -- internal-hostname suffixes -----------------------------------------------

def test_dot_local_suffix_blocked():
    assert _blocked("http://my-printer.local/")


def test_dot_internal_suffix_blocked():
    assert _blocked("http://service.internal/")


# -- legitimate public URLs must be allowed -----------------------------------

def test_ordinary_https_url_allowed():
    assert _allowed("https://example.com/")


def test_public_ip_literal_allowed():
    assert _allowed("http://8.8.8.8/")


def test_url_with_path_and_query_allowed():
    assert _allowed("https://api.github.com/repos/anthropics/claude-code?tab=readme")


def test_standard_dotted_quad_public_ip_is_not_flagged_as_encoded():
    # A normal 4-octet public IP literal isn't "numeric-encoded" in the
    # suspicious sense -- only the alternate/shorthand forms are.
    result = is_safe_public_url("http://8.8.8.8/", resolve_dns=False)
    assert result.safe is True
    assert "encoded" not in (result.reason or "")


# -- redirect revalidation ----------------------------------------------------

def test_revalidate_redirect_blocks_internal_target():
    result = revalidate_redirect("http://127.0.0.1/internal-api")
    assert result.safe is False


def test_revalidate_redirect_allows_public_target():
    result = is_safe_public_url("https://example.com/redirected", resolve_dns=False)
    assert result.safe is True


# -- real DNS resolution (network-touching, kept minimal) ---------------------

def test_real_dns_resolution_allows_a_known_public_domain():
    result = is_safe_public_url("https://example.com/")
    assert result.safe is True
    assert len(result.resolved_ips) > 0


def test_real_dns_resolution_blocks_localhost_localdomain():
    result = is_safe_public_url("http://localhost.localdomain/")
    assert result.safe is False


def test_real_dns_resolution_handles_nxdomain_gracefully():
    result = is_safe_public_url("http://this-domain-should-not-exist-abc123xyz.invalid/")
    assert result.safe is False
    assert "dns" in result.reason.lower() or "resolution" in result.reason.lower()
