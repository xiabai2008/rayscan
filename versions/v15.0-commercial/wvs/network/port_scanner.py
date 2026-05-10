"""异步端口扫描器"""
import asyncio
from typing import List, Set
import socket


class PortScanner:
    """基于 asyncio 的异步端口扫描器"""
    
    def __init__(self, concurrency: int = 100, timeout: float = 2.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.open_ports: Set[int] = set()
    
    async def scan_port(self, host: str, port: int) -> bool:
        """扫描单个端口"""
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
    
    async def scan_range(self, host: str, ports: List[int]) -> List[int]:
        """扫描端口范围"""
        semaphore = asyncio.Semaphore(self.concurrency)
        self.open_ports.clear()
        
        async def scan_with_limit(port: int):
            async with semaphore:
                if await self.scan_port(host, port):
                    self.open_ports.add(port)
                    print(f"  [+] Port {port} open")
        
        await asyncio.gather(*[scan_with_limit(p) for p in ports])
        return sorted(self.open_ports)
    
    def scan(self, host: str, start_port: int = 1, end_port: int = 1000) -> List[int]:
        """同步接口 - 扫描端口范围"""
        ports = list(range(start_port, end_port + 1))
        return asyncio.run(self.scan_range(host, ports))


class ServiceRecognizer:
    """简单服务识别（基于端口）"""
    
    COMMON_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }
    
    @classmethod
    def recognize(cls, port: int) -> str:
        return cls.COMMON_SERVICES.get(port, "Unknown")
