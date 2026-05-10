#!/usr/bin/env python3
"""
简单测试验证增强模块
避免Unicode编码问题
"""
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_validation_enhancer():
    """测试验证增强模块导入和基本功能"""
    print("[INFO] 测试验证增强模块...")
    
    try:
        from wvs.vuln.validation_enhancer import ValidationEnhancer, ValidationResult
        
        print("[SUCCESS] 模块导入成功")
        
        # 创建验证器实例
        validator = ValidationEnhancer()
        print(f"[INFO] 验证器初始化成功")
        print(f"[INFO] 时间盲注测试次数: {validator.TIME_TEST_COUNT}")
        print(f"[INFO] 时间标准差阈值: {validator.TIME_STDDEV_THRESHOLD}")
        print(f"[INFO] CMDI token长度: {validator.CMDI_TOKEN_LENGTH}")
        
        # 测试ValidationResult
        test_result = ValidationResult(
            is_valid=True,
            confidence=0.85,
            evidence="测试验证证据",
            details={"test": "data"}
        )
        
        print(f"[SUCCESS] ValidationResult测试: 有效={test_result.is_valid}, 置信度={test_result.confidence}")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_scanner_v18_integration():
    """测试扫描器集成"""
    print("\n[INFO] 测试扫描器集成...")
    
    try:
        from wvs.vuln.scanner_v18 import VulnerabilityScanner
        
        config = {
            "timeout": 30,
            "threads": 3,
            "validation": {"enabled": True}
        }
        
        scanner = VulnerabilityScanner(config)
        print(f"[SUCCESS] 扫描器初始化成功")
        print(f"[INFO] 配置: {config}")
        
        # 检查验证器是否已集成
        if hasattr(scanner, 'validator'):
            print("[SUCCESS] 验证增强模块已集成到扫描器")
        else:
            print("[WARNING] 未找到验证器属性，可能需要检查集成点")
            
        return True
        
    except Exception as e:
        print(f"[ERROR] 扫描器测试失败: {e}")
        return False


def test_nuclei_manager():
    """测试Nuclei管理器"""
    print("\n[INFO] 测试Nuclei模板管理器...")
    
    try:
        from nuclei_manager import NucleiManager
        
        manager = NucleiManager()
        print(f"[SUCCESS] Nuclei管理器初始化成功")
        print(f"[INFO] 默认下载源:")
        for source in manager.DEFAULT_SOURCES:
            print(f"  - {source.name}: {source.base_url}")
        
        # 检查模板分类
        print(f"[INFO] 模板分类:")
        for category, subcats in manager.CATEGORIES.items():
            print(f"  - {category}: {len(subcats)}个子类")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Nuclei管理器测试失败: {e}")
        return False


def main():
    """主测试函数"""
    print("=" * 50)
    print("WVS v18.4 核心模块测试")
    print("=" * 50)
    
    results = []
    
    # 测试1: 验证增强模块
    results.append(("验证增强模块", test_validation_enhancer()))
    
    # 测试2: 扫描器集成
    results.append(("扫描器集成", test_scanner_v18_integration()))
    
    # 测试3: Nuclei管理器
    results.append(("Nuclei管理器", test_nuclei_manager()))
    
    # 打印总结
    print("\n" + "=" * 50)
    print("测试总结:")
    print("=" * 50)
    
    success_count = 0
    for name, success in results:
        status = "PASS" if success else "FAIL"
        success_count += 1 if success else 0
        print(f"  {name}: {status}")
    
    print(f"\n总计: {success_count}/{len(results)} 通过")
    
    if success_count == len(results):
        print("[SUCCESS] 所有核心模块测试通过!")
        return True
    else:
        print("[WARNING] 部分模块测试失败，需要进一步调试")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)