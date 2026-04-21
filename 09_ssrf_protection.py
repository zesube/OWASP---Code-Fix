import ipaddress
import socket
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"api.example.com"}


def _resolve_public_ips(hostname: str):
    addresses = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
        raw_ip = sockaddr[0]
        ip = ipaddress.ip_address(raw_ip)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError("Host resolves to a non-public IP address.")
        addresses.append(ip)
    return addresses


def fetch_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed.")

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials are not allowed.")

    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host is not on the allowlist.")

    _resolve_public_ips(parsed.hostname)

    response = requests.get(
        url,
        timeout=3,
        allow_redirects=False,
        headers={"Accept": "application/json"},
    )
    response.raise_for_status()
    return response.text
