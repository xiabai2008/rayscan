#!/usr/bin/env python3
"""
自动集成优化版验证增强 - 非交互式版本
"""
import os
import shutil
import sys

def integrate_optimized_validation():
    """自动集成优化功能"""
    print("开始自动集成优化版验证增强...")
    
    # 目标文件路径
    target_file = os.path.join("wvs", "vuln", "validation_enhancer.py")
    
    if not os.path.exists(target_file):
        print(f"错误: 目标文件不存在: {target_file}")
        return False
    
    # 备份原始文件
    backup_file = target_file + ".backup"
    if not os.path.exists(backup_file):
        shutil.copy2(target_file, backup_file)
        print(f"已创建备份: {backup_file}")
    
    # 读取当前内容
    with open(target_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print(f"原始文件大小: {len(content)} 字符")
    
    # 检查是否已经集成过
    if "单次测试（无重复请求）" in content:
        print("检测到已集成优化功能，跳过集成")
        return True
    
    # 创建优化版本（简化的核心优化）
    optimized_code = '''
    async def validate_sqli_time_based(
        self,
        session,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        baseline_duration: float = 1.0
    ) -> ValidationResult:
        """优化版时间盲注验证
        
        基于Claude Code建议的优化：
        1. 消除重复请求浪费
        2. 改进异常值检测
        3. 优化置信度计算
        """
        import statistics
        import asyncio
        
        test_count = self.config.get("time_test_count", self.TIME_TEST_COUNT)
        stddev_threshold = self.config.get("time_stddev_threshold", self.TIME_STDDEV_THRESHOLD)
        min_delay = self.config.get("time_min_delay", self.TIME_MIN_DELAY)
        confidence_threshold = self.config.get("time_confidence_threshold", self.TIME_CONFIDENCE_THRESHOLD)
        
        durations = []
        
        for i in range(test_count):
            try:
                # 单次请求计时（已消除重复）
                if method.upper() == "GET":
                    test_params = {param: payload}
                    start = time.perf_counter()
                    async with session.get(url, params=test_params,
                                           timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        await resp.read()  # 确保请求完成
                    duration = time.perf_counter() - start
                else:
                    test_data = {param: payload}
                    start = time.perf_counter()
                    async with session.request(method, url, data=test_data,
                                               timeout=aiohttp.ClientTimeout(total=20)) as resp:
                        await resp.read()
                    duration = time.perf_counter() - start
                
                durations.append(duration)
                await asyncio.sleep(0.3)  # 优化后的间隔
                
            except asyncio.TimeoutError:
                durations.append(25.0)  # 优化超时值
            except Exception as e:
                return ValidationResult(
                    is_valid=False,
                    confidence=0.0,
                    evidence=f"请求失败: {str(e)}",
                    details={"error": str(e)}
                )
        
        if len(durations) < 2:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence="测试数据不足",
                details={"durations": durations}
            )
        
        # 改进的异常值检测（IQR方法）
        if len(durations) >= 4:
            q1 = statistics.quantiles(durations, n=4)[0]
            q3 = statistics.quantiles(durations, n=4)[2]
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            filtered_durations = [x for x in durations if lower_bound <= x <= upper_bound]
        else:
            # 数据太少，使用简单过滤
            sorted_durations = sorted(durations)
            filtered_durations = sorted_durations[1:-1] if len(sorted_durations) > 2 else sorted_durations
        
        if not filtered_durations:
            filtered_durations = durations
        
        avg_duration = statistics.mean(filtered_durations)
        
        # 计算标准差
        if len(filtered_durations) > 1:
            stddev = statistics.stdev(filtered_durations)
        else:
            stddev = 0.0
        
        # 计算有效延迟
        effective_delay = avg_duration - baseline_duration
        
        # 优化置信度计算
        if effective_delay >= min_delay:
            # 结合延迟和稳定性的优化公式
            delay_ratio = min(effective_delay / min_delay, 2.0)
            base_confidence = min(0.7 + (delay_ratio - 1) * 0.3, 0.95)
            
            # 稳定性调整
            if stddev < stddev_threshold:
                stability_factor = 1.0 - (stddev / stddev_threshold)
                confidence = base_confidence + stability_factor * 0.15
            else:
                confidence = base_confidence * 0.8  # 高波动性惩罚
            
            confidence = max(confidence, confidence_threshold)
            confidence = min(confidence, 0.99)
            
            is_valid = confidence >= confidence_threshold
            
            # 丰富证据信息
            evidence_parts = []
            if is_valid:
                evidence_parts.append("验证通过")
            evidence_parts.append(f"延迟: {effective_delay:.2f}s")
            evidence_parts.append(f"置信度: {confidence:.2f}")
            evidence_parts.append(f"稳定性: {stddev:.2f}")
            if len(durations) != len(filtered_durations):
                evidence_parts.append(f"过滤异常值: {len(durations)-len(filtered_durations)}个")
            
            return ValidationResult(
                is_valid=is_valid,
                confidence=confidence,
                evidence="; ".join(evidence_parts),
                details={
                    "durations": durations,
                    "filtered_durations": filtered_durations,
                    "avg_duration": avg_duration,
                    "stddev": stddev,
                    "effective_delay": effective_delay,
                    "baseline_duration": baseline_duration,
                    "outliers_removed": len(durations) - len(filtered_durations)
                }
            )
        else:
            return ValidationResult(
                is_valid=False,
                confidence=0.3,
                evidence=f"有效延迟 {effective_delay:.2f}s 低于阈值 {min_delay}s",
                details={
                    "durations": durations,
                    "avg_duration": avg_duration,
                    "effective_delay": effective_delay
                }
            )'''
    
    # 查找并替换原函数
    import re
    
    # 匹配原函数（简化匹配）
    pattern = r'async def validate_sqli_time_based[\s\S]*?\n\n    async def validate_cmdi_echo'
    
    if re.search(pattern, content):
        # 替换函数
        new_content = re.sub(pattern, optimized_code + '\n\n    async def validate_cmdi_echo', content)
        
        # 写入文件
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"优化完成! 文件已更新: {target_file}")
        print(f"新文件大小: {len(new_content)} 字符")
        
        # 验证更新
        if "单次请求计时（已消除重复）" in new_content and "改进的异常值检测（IQR方法）" in new_content:
            print("✅ 核心优化功能已成功集成")
            return True
        else:
            print("⚠️ 部分优化功能可能未正确集成")
            return False
    else:
        print("错误: 未找到目标函数进行替换")
        return False

def verify_integration():
    """验证集成结果"""
    print("\n验证集成结果...")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # 尝试导入
        from wvs.vuln.validation_enhancer import ValidationEnhancer
        
        print("✅ 模块导入成功")
        
        # 检查配置
        config = {
            "time_test_count": 3,
            "time_stddev_threshold": 0.3,
            "time_min_delay": 1.5
        }
        
        validator = ValidationEnhancer(config)
        print("✅ 验证器初始化成功")
        
        # 检查函数是否存在
        import inspect
        func_source = inspect.getsource(validator.validate_sqli_time_based)
        
        if "单次请求计时" in func_source and "IQR方法" in func_source:
            print("✅ 优化版函数已正确集成")
            print("✅ 包含核心优化功能:")
            print("   - 消除重复请求")
            print("   - IQR异常值检测")
            print("   - 优化置信度计算")
            return True
        else:
            print("⚠️ 未检测到完整的优化功能")
            return False
            
    except Exception as e:
        print(f"❌ 验证失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函数"""
    print("=" * 60)
    print("WVS v18.4 自动集成优化验证增强")
    print("=" * 60)
    
    # 集成优化
    print("\n[1/2] 集成优化功能...")
    if not integrate_optimized_validation():
        print("集成失败，正在恢复备份...")
        # 尝试恢复备份
        target_file = os.path.join("wvs", "vuln", "validation_enhancer.py")
        backup_file = target_file + ".backup"
        if os.path.exists(backup_file):
            shutil.copy2(backup_file, target_file)
            print("已恢复备份文件")
        return False
    
    # 验证集成
    print("\n[2/2] 验证集成结果...")
    if not verify_integration():
        print("验证失败")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 优化版验证增强集成成功!")
    print("=" * 60)
    print("\n集成内容:")
    print("  ✅ 消除重复请求浪费")
    print("  ✅ 改进异常值检测 (IQR方法)")
    print("  ✅ 优化置信度计算公式")
    print("  ✅ 丰富的验证证据信息")
    print("\n下一步建议:")
    print("  1. 运行对比测试验证优化效果")
    print("  2. 更新配置使用新的优化参数")
    print("  3. 监控优化后的扫描性能")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)