"""被动代理 TLS 拦截支持:按需 CA + 每域名叶证书。

设计:
- 依赖可选的 `cryptography`(>=42);未安装时由代理优雅降级为隧道转发(不检测)
- CA 证书首次启用拦截时生成并持久化(ca.pem / ca_key.pem)
- 叶证书按 CONNECT 目标主机名按需签发(SAN=主机名/IP),落盘缓存避免重复签发
- 客户端(浏览器)需信任 ca.pem 后,HTTPS 流量才能被解密检测(信任命令见 trust_instructions)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import ssl
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - 可选依赖
    HAS_CRYPTOGRAPHY = False

CA_CERT_NAME = "ca.pem"
CA_KEY_NAME = "ca_key.pem"
CA_SUBJECT_CN = "RayScan Passive Proxy CA"
CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365


class CertAuthority:
    """管理 MITM CA 证书与按需签发的叶证书(线程安全)。

    用法:
        ca = CertAuthority(ca_dir)
        ca.ensure_ca()                      # 加载或生成 CA
        cert, key = ca.get_leaf_paths(host) # 按需签发叶证书(缓存)
        ctx = ca.server_ssl_context(host)   # 可直接用于服务端 TLS 升级
    """

    def __init__(self, ca_dir):
        self.ca_dir = Path(ca_dir)
        self._lock = threading.Lock()
        self._ca_cert = None
        self._ca_key = None
        self._leaf_cache: Dict[str, Tuple[Path, Path]] = {}

    @staticmethod
    def available() -> bool:
        """cryptography 是否可用。"""
        return HAS_CRYPTOGRAPHY

    @property
    def ca_cert_pem(self) -> bytes:
        if self._ca_cert is None:
            raise RuntimeError("CA 尚未初始化,请先调用 ensure_ca()")
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)

    def ensure_ca(self) -> None:
        """加载或生成 CA 并持久化到 ca_dir。"""
        with self._lock:
            if self._ca_cert is not None:
                return
            if not HAS_CRYPTOGRAPHY:
                raise RuntimeError("TLS 拦截需要 cryptography 库: pip install 'rayscan[tls]'")
            self.ca_dir.mkdir(parents=True, exist_ok=True)
            cert_path = self.ca_dir / CA_CERT_NAME
            key_path = self.ca_dir / CA_KEY_NAME
            if cert_path.exists() and key_path.exists():
                self._ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                self._ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
                logger.debug("[Passive] 已加载既有 CA: %s", cert_path)
                return

            now = datetime.now(timezone.utc)
            key = ec.generate_private_key(ec.SECP256R1())
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_SUBJECT_CN)])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256())
            )
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            self._ca_cert, self._ca_key = cert, key
            logger.info("[Passive] 已生成 MITM CA: %s (请将 ca.pem 导入客户端信任列表)", cert_path)

    def get_leaf_paths(self, host: str) -> Tuple[Path, Path]:
        """为主机签发(或读取缓存的)叶证书,返回 (cert_path, key_path)。"""
        host = self._normalize_host(host)
        with self._lock:
            cached = self._leaf_cache.get(host)
        if cached:
            return cached

        self.ensure_ca()
        leaves_dir = self.ca_dir / "leaves"
        leaves_dir.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", host)
        cert_path = leaves_dir / f"{safe_name}.pem"
        key_path = leaves_dir / f"{safe_name}.key"
        with self._lock:
            if cert_path.exists() and key_path.exists():
                self._leaf_cache[host] = (cert_path, key_path)
                return cert_path, key_path

        now = datetime.now(timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        san_names = [x509.DNSName(host)]
        try:
            ip = ipaddress.ip_address(host)
            san_names.insert(0, x509.IPAddress(ip))
        except ValueError:
            pass
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=LEAF_VALIDITY_DAYS))
            .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        with self._lock:
            self._leaf_cache[host] = (cert_path, key_path)
        logger.debug("[Passive] 已为 %s 签发叶证书", host)
        return cert_path, key_path

    def server_ssl_context(self, host: str) -> ssl.SSLContext:
        """构造用于伪装目标站点的服务端 TLS 上下文(不设 ALPN,强制 HTTP/1.1)。"""
        cert_path, key_path = self.get_leaf_paths(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx

    @staticmethod
    def _normalize_host(host: str) -> str:
        return host.lower().strip().rstrip(".").lstrip("[").rstrip("]")


def default_ca_dir() -> Path:
    """默认 CA 存放目录(~/.rayscan/ca,已被 .gitignore 覆盖)。"""
    return Path.home() / ".rayscan" / "ca"


def trust_instructions(ca_cert_path: Path) -> str:
    """返回当前平台信任 CA 证书的命令提示。"""
    ca = str(ca_cert_path)
    if sys.platform.startswith("win"):
        return f'certutil -addstore -user Root "{ca}"'
    if sys.platform == "darwin":
        return f'security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain "{ca}"'
    return (
        f'sudo cp "{ca}" /usr/local/share/ca-certificates/rayscan.crt && sudo update-ca-certificates '
        f"(Chrome/Firefox 需在各自证书管理器中另行导入)"
    )


def parse_authority(authority: str) -> Tuple[str, int]:
    """解析 CONNECT authority("host:port" / "host" / "[::1]:443")。"""
    authority = authority.strip()
    if authority.startswith("["):
        host, _, rest = authority.partition("]")
        host = host.lstrip("[")
        port = int(rest.lstrip(":")) if rest.lstrip(":").isdigit() else 443
        return host, port
    host, sep, port_s = authority.rpartition(":")
    if not sep or not port_s.isdigit():
        return authority, 443
    return host, int(port_s)
