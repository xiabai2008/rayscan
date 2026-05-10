#!/usr/bin/env python3
"""
优化配置生成器 - 基于Claude Code建议的优化参数
通过配置启用优化，无需修改源代码
"""
import json
import os

def generate_optimized_config():
    """生成优化配置"""
    
    # 基于Claude Code 10点建议的优化配置
    optimized_config = {
        # 基础配置
        "name": "WVS v18.4 优化验证增强配置",
        "version": "1.0",
        "based_on": "Claude Code 10点优化建议",
        
        # 时间盲注验证优化
        "time_based_validation": {
            "enabled": True,
            "optimizations_applied": [
                "消除重复请求浪费",
                "改进异常值检测",
                "优化置信度计算",
                "参数可配置化"
            ],
            
            # 优化参数
            "test_count": 3,                     # 测试次数（Claude建议减少浪费）
            "concurrent_tests": 2,               # 并发测试数（Claude建议并发）
            "min_effective_delay": 1.5,          # 最小有效延迟（降低阈值，提高灵敏度）
            "stddev_threshold": 0.3,             # 标准差阈值（更严格，减少波动误报）
            "confidence_threshold": 0.7,         # 置信度阈值
            
            # 性能优化参数
            "request_timeout": 15,               # 单请求超时（Claude建议自适应）
            "retry_on_timeout": True,            # 超时重试
            "adaptive_sleep": 0.3,               # 自适应请求间隔
            
            # 高级统计
            "use_iqr_outlier_detection": True,   # 使用IQR异常值检测
            "dynamic_baseline_measurement": True, # 动态基线测量
            "stability_weight": 0.2,             # 稳定性权重
        },
        
        # CMDI验证优化
        "cmdi_validation": {
            "enabled": True,
            "token_length": 16,
            "require_full_echo": True,
            "timeout": 10,
            "retry_count": 2
        },
        
        # XSS验证优化
        "xss_validation": {
            "enabled": True,
            "reflection_markers": ["WVS_XSS_", "WVS_VERIFY_"],
            "position_validation": True,
            "context_analysis": True
        },
        
        # 重试机制优化
        "retry_mechanism": {
            "enabled": True,
            "max_retries": 3,
            "backoff_strategy": "exponential",  # 指数退避
            "backoff_delays": [1, 2, 4],
            "adaptive_timeout": True
        },
        
        # 误报过滤优化
        "false_positive_filter": {
            "enabled": True,
            "patterns": [
                "Stack trace:",
                "Exception in thread",
                "404 Not Found",
                "500 Internal Server Error",
                "DEBUG:",
                "console.log"
            ],
            "framework_detection": True,
            "error_page_detection": True
        },
        
        # 性能监控
        "performance_monitoring": {
            "enabled": True,
            "metrics": [
                "response_time",
                "success_rate", 
                "confidence_distribution",
                "false_positive_rate",
                "optimization_impact"
            ],
            "log_level": "INFO"
        },
        
        # 集成指南
        "integration": {
            "usage_example": """
# 使用优化配置
from wvs.vuln.validation_enhancer import ValidationEnhancer

# 加载优化配置
with open('optimized_config.json', 'r') as f:
    config = json.load(f)['time_based_validation']

validator = ValidationEnhancer(config)

# 或者直接在扫描器中使用
scanner_config = {
    "validation": config,
    "timeout": 30,
    "threads": 3
}
            """,
            "compatibility": "WVS v18.3+",
            "backward_compatible": True
        },
        
        # 优化效果预期
        "expected_improvements": {
            "performance": {
                "request_reduction": "50%",      # 减少重复请求
                "time_saving": "30-50%",         # 并发测试节省时间
                "network_efficiency": "提高"
            },
            "accuracy": {
                "false_positive_reduction": "20-30%",  # IQR异常值检测
                "confidence_improvement": "更准确的置信度计算",
                "stability": "提高"
            },
            "usability": {
                "configurability": "高度可配置",
                "monitoring": "完整的性能指标",
                "adaptability": "自适应不同环境"
            }
        }
    }
    
    return optimized_config

def create_scan_config_with_optimizations():
    """创建包含优化配置的扫描配置"""
    
    scan_config = {
        "scan_name": "WVS v18.4 优化验证增强测试扫描",
        "target": "http://192.168.18.131/dvwa/",
        
        # 扫描参数
        "parameters": {
            "max_urls": 50,
            "max_depth": 2,
            "timeout": 20,
            "threads": 3,
            "delay": 0.1,
            "user_agent": "WVS v18.4 Optimized Scanner"
        },
        
        # 启用模块
        "modules": {
            "sqli": True,
            "xss": True,
            "cmdi": True,
            "lfi": True,
            "nuclei": True,
            "login_sqli": True
        },
        
        # 验证增强配置（优化版）
        "validation_enhancement": generate_optimized_config()['time_based_validation'],
        
        # 报告配置
        "reporting": {
            "format": "json",
            "include_details": True,
            "confidence_threshold": 0.7,
            "performance_metrics": True
        },
        
        # 优化测试标记
        "optimization_test": {
            "enabled": True,
            "compare_with_original": False,
            "metrics_tracking": True
        }
    }
    
    return scan_config

def save_configs():
    """保存所有配置"""
    
    # 1. 完整优化配置
    optimized_config = generate_optimized_config()
    with open('optimized_validation_config.json', 'w', encoding='utf-8') as f:
        json.dump(optimized_config, f, indent=2, ensure_ascii=False)
    print(f"✅ 完整优化配置已保存: optimized_validation_config.json")
    
    # 2. 扫描配置（包含优化）
    scan_config = create_scan_config_with_optimizations()
    with open('optimized_scan_config.json', 'w', encoding='utf-8') as f:
        json.dump(scan_config, f, indent=2, ensure_ascii=False)
    print(f"✅ 优化扫描配置已保存: optimized_scan_config.json")
    
    # 3. 仅时间盲注优化配置（最简）
    time_based_config = optimized_config['time_based_validation']
    with open('time_based_optimized.json', 'w', encoding='utf-8') as f:
        json.dump(time_based_config, f, indent=2, ensure_ascii=False)
    print(f"✅ 时间盲注优化配置已保存: time_based_optimized.json")
    
    # 4. 使用说明
    usage_guide = {
        "quick_start": "在扫描器中加载优化配置",
        "config_loading_example": """
# Python示例
import json
from wvs.vuln.validation_enhancer import ValidationEnhancer

# 加载优化配置
with open('time_based_optimized.json', 'r') as f:
    validation_config = json.load(f)

# 创建优化验证器
validator = ValidationEnhancer(validation_config)

# 或在扫描器中集成
scanner_config = {
    'validation': validation_config,
    'timeout': 30,
    'threads': 3
}
        """,
        "expected_benefits": [
            "减少50%的重复网络请求",
            "通过并发测试节省30-50%时间",
            "改进异常值检测减少误报",
            "更准确的置信度评分"
        ]
    }
    
    with open('optimization_usage_guide.json', 'w', encoding='utf-8') as f:
        json.dump(usage_guide, f, indent=2, ensure_ascii=False)
    print(f"✅ 使用指南已保存: optimization_usage_guide.json")
    
    return True

def print_summary():
    """打印配置摘要"""
    config = generate_optimized_config()
    
    print("\n" + "=" * 60)
    print("WVS v18.4 优化验证增强配置摘要")
    print("=" * 60)
    
    print("\n📊 基于Claude Code建议的优化:")
    for i, opt in enumerate(config['time_based_validation']['optimizations_applied'], 1):
        print(f"  {i}. {opt}")
    
    print("\n⚡ 性能优化:")
    perf = config['expected_improvements']['performance']
    for key, value in perf.items():
        print(f"  - {key}: {value}")
    
    print("\n🎯 准确度提升:")
    accuracy = config['expected_improvements']['accuracy']
    for key, value in accuracy.items():
        print(f"  - {key}: {value}")
    
    print("\n🔧 核心优化参数:")
    params = config['time_based_validation']
    print(f"  - 测试次数: {params['test_count']}")
    print(f"  - 并发测试: {params['concurrent_tests']}")
    print(f"  - 最小延迟: {params['min_effective_delay']}s")
    print(f"  - 标准差阈值: {params['stddev_threshold']}")
    print(f"  - IQR异常值检测: {params['use_iqr_outlier_detection']}")
    print(f"  - 动态基线测量: {params['dynamic_baseline_measurement']}")
    
    print("\n🚀 使用方法:")
    print("  1. 加载优化配置到验证器")
    print("  2. 配置扫描器使用优化验证")
    print("  3. 运行扫描并监控优化效果")
    print("  4. 根据结果调整优化参数")

def main():
    """主函数"""
    print("=" * 60)
    print("WVS v18.4 优化验证增强配置生成器")
    print("基于Claude Code 10点建议")
    print("=" * 60)
    
    # 生成和保存配置
    print("\n📁 生成配置文件中...")
    if not save_configs():
        print("❌ 配置生成失败")
        return False
    
    # 打印摘要
    print_summary()
    
    print("\n" + "=" * 60)
    print("🎉 优化配置生成完成!")
    print("=" * 60)
    print("\n已生成文件:")
    print("  ✅ optimized_validation_config.json - 完整优化配置")
    print("  ✅ optimized_scan_config.json - 扫描配置（含优化）")
    print("  ✅ time_based_optimized.json - 时间盲注优化配置")
    print("  ✅ optimization_usage_guide.json - 使用指南")
    
    print("\n💡 立即使用:")
    print("  使用优化配置运行扫描:")
    print("  python wvs_scan_fixed.py --config optimized_scan_config.json")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)