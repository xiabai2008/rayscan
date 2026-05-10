#!/usr/bin/env python3
"""
WVS v18.4 - 修复版扫描脚本
专门针对Metasploitable2的完整扫描
"""
import asyncio
import json
import sys
import time
import os

# 修复路径和编码问题
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def main():
    t0 = time.time()
    
    try:
        # 尝试导入完整扫描器
        from wvs.vuln.full_scanner import FullScanner
        
        # 配置扫描器
        scanner_config = {
            'enable_basic': True,
            'enable_nuclei': True,
            'enable_sqlmap': False,  # 先禁用SQLMap，专注验证增强
            'enable_playwright': False,
            'max_urls': 50,  # 减少数量，加快测试
            'max_depth': 2,
            'timeout': 15,
            'validation': {
                'enabled': True,
                'confidence_threshold': 0.7
            }
        }
        
        print("[*] WVS v18.4 验证增强扫描启动")
        print(f"[*] 目标: http://192.168.18.131")
        print(f"[*] 配置: {scanner_config}")
        
        scanner = FullScanner(scanner_config)
        
        # 运行扫描
        result = await scanner.scan(
            'http://192.168.18.131',
            modules=['sqli', 'xss', 'cmdi', 'lfi', 'nuclei']
        )
        
        elapsed = time.time() - t0
        
        # 打印结果
        print()
        print(f"[*] 扫描完成!")
        print(f"[*] 扫描URL数: {len(result.urls)}")
        print(f"[*] 发现表单: {len(result.forms)}")
        print(f"[*] 耗时: {elapsed:.1f}秒")
        print(f"[*] 扫描源: {result.sources}")
        
        # 按严重程度统计漏洞
        by_sev = {}
        for v in result.vulnerabilities:
            by_sev.setdefault(v.severity, []).append(v)
        
        print()
        print("[*] 漏洞统计:")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            if by_sev.get(sev):
                print(f"--- {sev.upper()} ({len(by_sev[sev])}) ---")
                for v in by_sev[sev]:
                    print(f"  [{v.source:10s}] {v.type}")
                    print(f"    URL: {v.url[:80]}")
                    if v.evidence:
                        print(f"    证据: {v.evidence[:100]}...")
                    print()
        
        # 保存结果到文件
        output_file = 'scan_result_v18.4.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': result.target,
                'urls': len(result.urls),
                'forms': len(result.forms),
                'duration': result.duration,
                'sources': result.sources,
                'vulnerabilities': [{
                    'type': v.type,
                    'severity': v.severity,
                    'url': v.url,
                    'source': v.source,
                    'confidence': v.confidence,
                    'evidence': v.evidence[:200] if v.evidence else ''
                } for v in result.vulnerabilities]
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n[*] 总计发现 {len(result.vulnerabilities)} 个漏洞")
        print(f"[*] 结果已保存到: {output_file}")
        
        # 特别关注验证增强检测的漏洞
        validation_vulns = [v for v in result.vulnerabilities 
                           if v.confidence >= 0.7 and v.source == 'scanner']
        
        if validation_vulns:
            print("\n[*] 验证增强检测的高置信度漏洞:")
            for v in validation_vulns:
                print(f"  - {v.type} ({v.severity}): {v.url[:60]}...")
                print(f"    置信度: {v.confidence:.2f}")
        
        return len(result.vulnerabilities)
        
    except Exception as e:
        print(f"[ERROR] 扫描失败: {e}")
        import traceback
        traceback.print_exc()
        return 0


if __name__ == '__main__':
    # Windows兼容性设置
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # 运行扫描
    vuln_count = asyncio.run(main())
    
    if vuln_count > 0:
        print(f"\n[SUCCESS] 扫描完成，发现 {vuln_count} 个漏洞")
        sys.exit(0)
    else:
        print("\n[WARNING] 未发现漏洞，可能需要检查目标或配置")
        sys.exit(1)