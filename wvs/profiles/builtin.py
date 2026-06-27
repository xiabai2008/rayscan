# Built-in Profile Definitions

BUILTIN_PROFILES = {
    "default": {
        "name": "default",
        "description": "均衡模式，全模块",
        "modules": {"enabled": [], "disabled": []},
        "params": {
            "rate": 10,
            "threads": 5,
            "timeout": 30,
            "crawl_depth": 3,
            "crawl_max_urls": 100,
            "verify_ssl": True,
        },
    },
    "src-quick": {
        "name": "src-quick",
        "description": "SRC快瞄 — 高灵敏度，快速出结果",
        "modules": {"enabled": ["sqli", "xss", "cmdi", "lfi"], "disabled": []},
        "params": {
            "rate": 20,
            "threads": 10,
            "timeout": 15,
            "crawl_depth": 2,
            "crawl_max_urls": 50,
            "verify_ssl": False,
        },
    },
    "pentest-full": {
        "name": "pentest-full",
        "description": "渗透测试，深度爬，全模块",
        "modules": {"enabled": [], "disabled": []},
        "params": {
            "rate": 5,
            "threads": 3,
            "timeout": 45,
            "crawl_depth": 4,
            "crawl_max_urls": 500,
            "verify_ssl": False,
        },
    },
    "sqli-only": {
        "name": "sqli-only",
        "description": "只扫SQL注入",
        "modules": {"enabled": ["sqli"], "disabled": []},
        "params": {
            "rate": 20,
            "threads": 10,
            "timeout": 30,
            "crawl_depth": 2,
            "crawl_max_urls": 100,
            "verify_ssl": False,
        },
    },
}
