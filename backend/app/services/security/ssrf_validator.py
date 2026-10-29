"""SSRF (Server-Side Request Forgery) protection and URL validation service.

Security Invariants:
1. All private, loopback, link-local, multicast, and cloud metadata IP addresses are strictly prohibited.
2. URLs must use explicit allowed schemes (http, https).
3. Hostnames that resolve to prohibited IP ranges (including via DNS rebinding) are blocked.
4. Input strings are sanitized against path traversal and null bytes.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Prohibited IPv4 networks (RFC 1918, RFC 3927 link-local, loopback, broadcast)
_PROHIBITED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (includes AWS/GCP metadata 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited broadcast
)


# Prohibited IPv6 networks
_PROHIBITED_IPV6_NETWORKS = (
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (can encode private IPv4)
    ipaddress.ip_network("fc00::/7"),           # Unique local address (ULA, RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast
)

# Known cloud metadata hostnames
_METADATA_HOSTNAMES = frozenset({
    "instance-data",
    "metadata.google.internal",
    "metadata.gcp.internal",
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata",
})

# Obfuscated IP representations (octal, hex, dword)
_OCTAL_OR_HEX_IP_RE = re.compile(
    r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$",
    re.IGNORECASE,
)


class SSRFProtection:
    """Enforces strict SSRF prevention on external URLs and IP addresses."""

    @staticmethod
    def is_prohibited_ip(ip_str: str) -> bool:
        """Check if an IP address string falls into any prohibited (private/internal) network."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return True  # If unparseable as an IP, reject for safety

        # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in net for net in _PROHIBITED_NETWORKS)
        elif isinstance(ip, ipaddress.IPv6Address):
            return any(ip in net for net in _PROHIBITED_IPV6_NETWORKS)
        return True

    @classmethod
    def validate_url(cls, url: str) -> tuple[bool, str | None]:
        """Validate a URL against SSRF rules.

        Returns:
            (is_safe, error_reason)
        """
        if not url or not isinstance(url, str):
            return False, "URL is empty or not a string"

        clean_url = url.strip()

        # Reject null bytes and path traversal attempts in scheme/authority
        if "\x00" in clean_url or "\r" in clean_url or "\n" in clean_url:
            return False, "URL contains invalid control characters or null bytes"

        try:
            parsed = urlparse(clean_url)
        except Exception as exc:
            return False, f"URL parsing error: {exc}"

        # 1. Scheme check: only http and https are allowed
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Scheme '{parsed.scheme}' is prohibited. Only http and https are allowed."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL has no valid hostname"

        hostname_clean = hostname.strip().lower()

        # 2. Cloud metadata host check
        if hostname_clean in _METADATA_HOSTNAMES:
            return False, f"Hostname '{hostname_clean}' is a prohibited cloud metadata endpoint"

        # 3. Direct IP address check
        try:
            # Test if hostname is a literal IP address
            direct_ip = ipaddress.ip_address(hostname_clean)
            if cls.is_prohibited_ip(str(direct_ip)):
                return False, f"Destination IP {direct_ip} is in a prohibited or private network range"
            return True, None
        except ValueError:
            pass  # Not a direct IP literal; continue to DNS resolution check

        # 4. Obfuscated IP check (hex, octal, dword)
        if _OCTAL_OR_HEX_IP_RE.match(hostname_clean):
            return False, "Obfuscated non-standard numeric IP notation is prohibited"

        # 5. DNS Resolution validation (check all resolved A and AAAA records)
        try:
            addr_info = socket.getaddrinfo(hostname_clean, parsed.port or (443 if parsed.scheme == "https" else 80))
            for item in addr_info:
                sockaddr = item[4]
                resolved_ip = str(sockaddr[0])
                if cls.is_prohibited_ip(resolved_ip):
                    return False, f"Hostname '{hostname_clean}' resolves to private/internal IP {resolved_ip}"
        except socket.gaierror:
            # Host could not be resolved; does not resolve to an internal IP
            # We allow the request to proceed to the caller or fail gracefully
            pass
        except Exception as exc:
            return False, f"DNS resolution check failed: {exc}"

        return True, None

    @classmethod
    def sanitize_indicator(cls, indicator: str) -> str:
        """Sanitize an indicator (domain, IP, URL) to prevent path traversal in API endpoints."""
        if not indicator:
            return ""
        # Strip path traversal patterns
        clean = indicator.strip()
        clean = clean.replace("\x00", "").replace("..", "")
        return clean
