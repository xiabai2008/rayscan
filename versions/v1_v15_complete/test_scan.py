import asyncio
import sys
sys.path.insert(0, '.')
from wvs.core.config import ScanConfig
from wvs.core.scanner import WVSScanner

config = ScanConfig(
    target='http://47.95.192.41:8082',
    port_range=(8082, 8082),
    max_depth=2,
    max_urls=20,
    timeout=15.0,
    output_dir='reports'
)
scanner = WVSScanner(config)
result = asyncio.run(scanner.scan())
print(f"Vulnerabilities found: {result['vulnerabilities']}")
