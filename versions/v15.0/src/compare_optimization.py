#!/usr/bin/env python3
"""
对比测试 - 优化前后性能对比
"""
import asyncio
import json
import time
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 测试目标
TEST_TARGET = "http://192.168.18.131/dvwa/vulnerabilities/sqli/"
TEST_PAYLOADS = [
    ("1' OR '1'='1", "基本SQL注入"),
    ("1' AND SLEEP(2)-- -", "时间盲注"),
    ("1' UNION SELECT 1,2,3-- -", "联合查询"),
    ("1' OR 1=1-- -", "注释符注入"),
    ("1' OR 'a'='a", "字符串注入")
]

async def test_with_config(config_name, config, session):
    """使用指定配置进行测试"""
    print(f"测试配置: {config_name}")
    
    try:
        from wvs.vuln.validation_enhancer import ValidationEnhancer
        
        # 创建验证器
        validator = ValidationEnhancer(config.get('validation', {}))
        
        results = []
        total_time = 0
        
        for payload, description in TEST_PAYLOADS:
            print(f"  {description}: {payload}")
            
            start_time = time.perf_counter()
            
            try:
                # 模拟验证测试
                test_params = {"id": payload, "Submit": "Submit"}
                headers = {"Cookie": "security=low"}
                
                # 发送请求
                req_start = time.perf_counter()
                async with session.get(TEST_TARGET, params=test_params, headers=headers, timeout=15) as resp:
                    content = await resp.text()
                response_time = time.perf_counter() - req_start
                
                # 简单漏洞分析
                is_vulnerable = False
                evidence = ""
                
                if resp.status == 200:
                    # 检查漏洞迹象
                    indicators = [
                        ("admin", "管理员信息"),
                        ("user", "用户信息"),
                        ("error", "错误信息"),
                        ("mysql", "MySQL"),
                        ("syntax", "语法错误")
                    ]
                    
                    for indicator, desc in indicators:
                        if indicator.lower() in content.lower():
                            is_vulnerable = True
                            evidence = desc
                            break
                
                test_time = time.perf_counter() - start_time
                total_time += test_time
                
                result = {
                    "payload": payload,
                    "description": description,
                    "response_time": response_time,
                    "total_time": test_time,
                    "is_vulnerable": is_vulnerable,
                    "evidence": evidence,
                    "status": resp.status
                }
                
                results.append(result)
                
                print(f"    响应时间: {response_time:.3f}s, 总时间: {test_time:.3f}s")
                print(f"    漏洞检测: {'是' if is_vulnerable else '否'} {evidence}")
                
            except Exception as e:
                print(f"    测试失败: {e}")
                results.append({
                    "payload": payload,
                    "description": description,
                    "error": str(e),
                    "is_vulnerable": False
                })
        
        # 统计结果
        successful_tests = [r for r in results if 'error' not in r]
        vulnerable_count = sum(1 for r in successful_tests if r.get('is_vulnerable', False))
        
        avg_response_time = 0
        if successful_tests:
            avg_response_time = sum(r['response_time'] for r in successful_tests) / len(successful_tests)
        
        return {
            "config_name": config_name,
            "total_tests": len(TEST_PAYLOADS),
            "successful_tests": len(successful_tests),
            "vulnerable_count": vulnerable_count,
            "detection_rate": vulnerable_count / len(successful_tests) if successful_tests else 0,
            "total_time": total_time,
            "avg_response_time": avg_response_time,
            "results": results,
            "config_used": config.get('validation', {})
        }
        
    except Exception as e:
        print(f"配置测试失败: {e}")
        return None

async def run_comparison():
    """运行对比测试"""
    print("运行优化对比测试...")
    print(f"测试目标: {TEST_TARGET}")
    print(f"测试payload数量: {len(TEST_PAYLOADS)}")
    
    import aiohttp
    
    # 测试配置
    test_configs = {
        "原始配置": {
            "validation": {
                "enabled": True,
                "time_test_count": 3,
                "time_stddev_threshold": 0.5,
                "time_min_delay": 2.0,
                "time_confidence_threshold": 0.7
            }
        },
        "优化配置": {
            "validation": {
                "enabled": True,
                "time_test_count": 3,
                "concurrent_tests": 2,
                "time_stddev_threshold": 0.3,
                "time_min_delay": 1.5,
                "time_confidence_threshold": 0.7,
                "use_iqr_outlier_detection": True,
                "dynamic_baseline_measurement": True,
                "adaptive_retry": True,
                "retry_count": 2
            }
        }
    }
    
    async with aiohttp.ClientSession() as session:
        results = []
        
        for config_name, config in test_configs.items():
            print(f"\n{'='*40}")
            result = await test_with_config(config_name, config, session)
            if result:
                results.append(result)
            print(f"{'='*40}")
        
        # 分析对比结果
        if len(results) == 2:
            return analyze_comparison(results[0], results[1])
    
    return None

def analyze_comparison(original_result, optimized_result):
    """分析对比结果"""
    print("\n" + "="*60)
    print("优化对比分析结果")
    print("="*60)
    
    improvements = []
    
    # 检测率对比
    orig_rate = original_result['detection_rate']
    opt_rate = optimized_result['detection_rate']
    detection_improvement = opt_rate - orig_rate
    
    if detection_improvement > 0:
        improvements.append(f"检测率提升: {detection_improvement*100:.1f}%")
    elif detection_improvement < 0:
        improvements.append(f"检测率下降: {detection_improvement*100:.1f}%")
    else:
        improvements.append("检测率持平")
    
    # 响应时间对比
    orig_time = original_result['avg_response_time']
    opt_time = optimized_result['avg_response_time']
    time_improvement = (orig_time - opt_time) / orig_time if orig_time > 0 else 0
    
    if time_improvement > 0:
        improvements.append(f"响应时间减少: {time_improvement*100:.1f}%")
    elif time_improvement < 0:
        improvements.append(f"响应时间增加: {abs(time_improvement)*100:.1f}%")
    else:
        improvements.append("响应时间持平")
    
    # 总时间对比
    orig_total = original_result['total_time']
    opt_total = optimized_result['total_time']
    total_improvement = (orig_total - opt_total) / orig_total if orig_total > 0 else 0
    
    if total_improvement > 0:
        improvements.append(f"总测试时间减少: {total_improvement*100:.1f}%")
    
    # 显示详细结果
    print(f"\n📊 原始配置结果:")
    print(f"  测试总数: {original_result['total_tests']}")
    print(f"  成功测试: {original_result['successful_tests']}")
    print(f"  发现漏洞: {original_result['vulnerable_count']}")
    print(f"  检测率: {original_result['detection_rate']*100:.1f}%")
    print(f"  平均响应时间: {original_result['avg_response_time']:.3f}s")
    print(f"  总测试时间: {original_result['total_time']:.3f}s")
    
    print(f"\n🚀 优化配置结果:")
    print(f"  测试总数: {optimized_result['total_tests']}")
    print(f"  成功测试: {optimized_result['successful_tests']}")
    print(f"  发现漏洞: {optimized_result['vulnerable_count']}")
    print(f"  检测率: {optimized_result['detection_rate']*100:.1f}%")
    print(f"  平均响应时间: {optimized_result['avg_response_time']:.3f}s")
    print(f"  总测试时间: {optimized_result['total_time']:.3f}s")
    
    print(f"\n📈 优化效果:")
    for improvement in improvements:
        print(f"  • {improvement}")
    
    # 生成报告
    report = {
        "comparison_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_target": TEST_TARGET,
        "test_payloads": TEST_PAYLOADS,
        "original_config": original_result,
        "optimized_config": optimized_result,
        "improvements": improvements,
        "summary": {
            "detection_rate_change": detection_improvement,
            "response_time_change": time_improvement,
            "total_time_change": total_improvement,
            "overall_improvement": len([i for i in improvements if '提升' in i or '减少' in i]) / len(improvements) if improvements else 0
        }
    }
    
    # 保存报告
    report_file = "optimization_comparison_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n📄 详细报告已保存: {report_file}")
    
    return report

async def main():
    """主函数"""
    print("="*60)
    print("WVS v18.4 优化前后性能对比测试")
    print("="*60)
    
    print(f"\n测试配置:")
    print("1. 原始配置 - 默认参数")
    print("2. 优化配置 - 基于Claude Code建议的优化参数")
    
    # 运行对比测试
    report = await run_comparison()
    
    if report:
        print("\n" + "="*60)
        print("对比测试完成!")
        print("="*60)
        
        # 总结
        improvements = report.get('improvements', [])
        positive_improvements = [i for i in improvements if '提升' in i or '减少' in i]
        
        if positive_improvements:
            print(f"\n✅ 优化效果显著: {len(positive_improvements)}/{len(improvements)}项改善")
            for imp in positive_improvements:
                print(f"   ✓ {imp}")
        else:
            print("\n⚠️  优化效果有限")
        
        print(f"\n📈 详细数据查看: optimization_comparison_report.json")
        
        return True
    else:
        print("\n❌ 对比测试失败")
        return False

if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    success = asyncio.run(main())
    sys.exit(0 if success else 1)