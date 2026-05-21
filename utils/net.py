"""
Network utility helpers — host resolution, CIDR expansion, banner grabbing.
"""

from __future__ import annotations
import socket
import ipaddress
from typing import List, Optional, Tuple
from utils.logger import get_logger

logger = get_logger(__name__)


def resolve_host(target: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        logger.debug(f"Resolution failed for {target}: {e}")
        return None


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IP strings."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [cidr]


def is_cidr(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return "/" in target
    except ValueError:
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send HTTP probe for web ports
            if port in (80, 8080, 8000, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:200]
            except socket.timeout:
                return ""
    except Exception:
        return ""


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


# Service fingerprint database (port → service name)
SERVICE_DB: dict = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 7001: "weblogic",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9200: "elasticsearch", 27017: "mongodb", 50070: "hadoop-hdfs",
}


def guess_service(port: int) -> str:
    return SERVICE_DB.get(port, "unknown")
