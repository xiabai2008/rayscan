import asyncio, aiohttp, re, sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

TARGET = "http://192.168.18.254"

async def recon():
    async with aiohttp.ClientSession() as s:
        for port in [80, 443, 8080, 8443]:
            try:
                async with s.get("http://192.168.18.254:" + str(port) + "/", timeout=aiohttp.ClientTimeout(total=5)) as r:
                    text = await r.text()
                    print("Port " + str(port) + ": " + str(r.status) + " len=" + str(len(text)))
                    title_m = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                    if title_m:
                        print("  Title: " + title_m.group(1).strip())
                    forms = re.findall(r"<form", text, re.IGNORECASE)
                    print("  Forms: " + str(len(forms)))
            except Exception as e:
                print("Port " + str(port) + ": " + type(e).__name__ + ": " + str(e))

asyncio.run(recon())
