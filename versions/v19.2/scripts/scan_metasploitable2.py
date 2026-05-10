#!/usr/bin/env python3
"""
WVS v19 — Metasploitable2 full scan test.

Scans all common services on a Metasploitable2 VM.
Usage: python scan_metasploitable2.py [metasploitable_ip]
Default IP: 192.168.18.131
"""
import asyncio
import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner, PoCGenerator
from wvs.models import ScanTarget
from wvs.reporting import ConsoleReporter, HTMLReporter, MarkdownReporter, JSONReporter


TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.18.131"

# Metasploitable2 common services
TARGETS = [
    f"http://{TARGET_IP}/mutillidae/",
    f"http://{TARGET_IP}/dvwa/",
    f"http://{TARGET_IP}/dav/",
    f"http://{TARGET_IP}/phpMyAdmin/",
    f"http://{TARGET_IP}/twiki/",
    f"http://{TARGET_IP}/tikiwiki/",
    f"http://{TARGET_IP}/",
]


async def scan_single(url: str, config: ConfigManager) -> dict:
    """Scan a single URL and return results."""
    print(f"\n{'='*60}")
    print(f"  Scanning: {url}")
    print(f"{'='*60}")

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url=url)
    start = time.perf_counter()

    try:
        result = await scanner.scan(target)
    except Exception as e:
        print(f"  [!] Scan error: {e}")
        await session.close()
        return {"url": url, "error": str(e), "vulns": []}

    elapsed = time.perf_counter() - start
    await session.close()

    # Generate PoCs for confirmed vulns
    pocs = []
    poc_gen = PoCGenerator(attacker_host=TARGET_IP, attacker_port=4444)
    for v in result.vulnerabilities:
        if v.confidence and v.confidence.value in ("high", "certain"):
            poc = poc_gen.generate(v)
            pocs.append(poc)

    return {
        "url": url,
        "duration": elapsed,
        "requests": result.requests_made,
        "endpoints": result.endpoints_found,
        "vulns": result.vulnerabilities,
        "pocs": pocs,
        "severity_count": result.severity_count,
        "vuln_type_count": result.vulnerability_count,
    }


async def main():
    config = ConfigManager()
    # Optimize for Metasploitable2 (local VM, no rate limiting needed)
    config.set("max_requests_per_second", 20)
    config.set("concurrent_endpoints", 5)
    config.set("crawl_depth", 3)
    config.set("crawl_max_urls", 200)
    config.set("timeout", 15)
    config.set("delay", 0.0)

    print("="*60)
    print("  WVS v19 — Metasploitable2 Full Scan")
    print(f"  Target IP: {TARGET_IP}")
    print(f"  Targets:   {len(TARGETS)} endpoints")
    print("="*60)

    all_results = []
    total_start = time.perf_counter()

    for url in TARGETS:
        result = await scan_single(url, config)
        all_results.append(result)
        if "error" not in result:
            print(f"  -> {len(result['vulns'])} vulns in {result.get('duration', 0):.1f}s")
        else:
            print(f"  -> FAILED: {result['error']}")

    total_elapsed = time.perf_counter() - total_start

    # ── Summary ──
    total_vulns = sum(
        len(r["vulns"]) for r in all_results if "vulns" in r
    )
    total_pocs = sum(
        len(r.get("pocs", [])) for r in all_results if "pocs" in r
    )

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"  Total time: {total_elapsed:.1f}s")
    print(f"  Targets scanned: {len(all_results)}")
    print(f"  Total vulns found: {total_vulns}")
    print(f"  PoCs generated: {total_pocs}")
    print(f"{'='*60}")

    # ── Per-target breakdown ──
    for r in all_results:
        if "error" in r:
            print(f"\n  {r['url']}")
            print(f"    Error: {r['error']}")
        else:
            print(f"\n  {r['url']}")
            print(f"    Duration: {r['duration']:.1f}s | "
                  f"Requests: {r['requests']} | "
                  f"Endpoints: {r['endpoints']}")
            if r["vulns"]:
                for v in r["vulns"]:
                    badge = f"[{v.severity.value.upper():<8}]"
                    print(f"    {badge} {v.type.value:<25} {v.title[:60]}")
            else:
                print(f"    [INFO]     No vulnerabilities found")

    # Save results
    output = {
        "scan_info": {
            "target": TARGET_IP,
            "targets_scanned": len(TARGETS),
            "duration": total_elapsed,
            "total_vulns": total_vulns,
            "total_pocs": total_pocs,
        },
        "results": [],
    }

    for r in all_results:
        entry = {"url": r["url"]}
        if "error" in r:
            entry["error"] = r["error"]
        else:
            entry["duration"] = r.get("duration", 0)
            entry["requests"] = r.get("requests", 0)
            entry["endpoints"] = r.get("endpoints", 0)
            entry["severity_count"] = r.get("severity_count", {})
            entry["vuln_type_count"] = r.get("vuln_type_count", {})
            entry["vulnerabilities"] = [v.to_dict() for v in r["vulns"]]
            entry["pocs"] = [
                {
                    "title": p.title,
                    "curl_command": p.curl_command,
                    "cvss_score": p.cvss_score,
                    "impact": p.impact_statement,
                }
                for p in r.get("pocs", [])
            ]
        output["results"].append(entry)

    output_file = Path(__file__).parent / "scan_results_metasploitable2.json"
    import json
    output_file.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n[+] Results saved: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
