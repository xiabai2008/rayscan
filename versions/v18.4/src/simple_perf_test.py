#!/usr/bin/env python3
"""
简单性能测试 - 无Unicode字符
"""
import asyncio
import time
import json
import sys

async def simple_test():
    """简单性能测试"""
    import aiohttp
    
    targets = [
        "http://192.168.18.131/dvwa/",
        "http://192.168.18.131/mutillidae/",
        "http://192.168.18.131/tikiwiki/"
    ]
    
    print("运行简单性能测试...")
    results = []
    
    # 测试1: 顺序扫描
    print("1. 顺序扫描测试")
    start = time.time()
    success = 0
    async with aiohttp.ClientSession() as session:
        for target in targets:
            try:
                async with session.get(target, timeout=10) as resp:
                    await resp.read()
                success += 1
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"  失败: {target} - {e}")
    
    sequential_time = time.time() - start
    sequential_rate = success / len(targets) if targets else 0
    results.append({
        "name": "sequential",
        "time": sequential_time,
        "success": success,
        "rate": sequential_rate,
        "throughput": success / sequential_time if sequential_time > 0 else 0
    })
    
    print(f"  耗时: {sequential_time:.2f}s, 成功率: {sequential_rate*100:.1f}%")
    
    # 测试2: 并发扫描
    print("2. 并发扫描测试 (3目标同时)")
    start = time.time()
    
    async def scan_target(t):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(t, timeout=10) as resp:
                    await resp.read()
            return True
        except Exception:
            return False
    
    tasks = [scan_target(t) for t in targets]
    concurrent_results = await asyncio.gather(*tasks)
    
    concurrent_time = time.time() - start
    concurrent_success = sum(1 for r in concurrent_results if r)
    concurrent_rate = concurrent_success / len(targets) if targets else 0
    
    results.append({
        "name": "concurrent",
        "time": concurrent_time,
        "success": concurrent_success,
        "rate": concurrent_rate,
        "throughput": concurrent_success / concurrent_time if concurrent_time > 0 else 0
    })
    
    print(f"  耗时: {concurrent_time:.2f}s, 成功率: {concurrent_rate*100:.1f}%")
    
    # 计算性能提升
    if sequential_time > 0 and concurrent_time > 0:
        speedup = sequential_time / concurrent_time
        throughput_improvement = (results[1]["throughput"] - results[0]["throughput"]) / results[0]["throughput"] * 100
        
        print("\n性能对比:")
        print(f"  速度提升: {speedup:.2f}x")
        print(f"  吞吐量提升: {throughput_improvement:.1f}%")
        
        if speedup > 1:
            print("  结论: 并发扫描显著提升性能!")
        else:
            print("  结论: 并发扫描效果有限")
    
    # 保存结果
    report = {
        "test_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": targets,
        "results": results,
        "summary": {
            "concurrent_speedup": sequential_time / concurrent_time if concurrent_time > 0 else 0,
            "recommendation": "使用并发扫描提高效率"
        }
    }
    
    with open("simple_perf_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n报告已保存: simple_perf_report.json")
    return report

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    report = asyncio.run(simple_test())