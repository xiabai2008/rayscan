#!/usr/bin/env python3
"""
集成优化版验证增强模块到WVS v18.4
"""
import os
import shutil
import sys

def backup_original_file():
    """备份原始文件"""
    original_path = os.path.join("wvs", "vuln", "validation_enhancer.py")
    backup_path = os.path.join("wvs", "vuln", "validation_enhancer_original.py")
    
    if os.path.exists(original_path):
        if os.path.exists(backup_path):
            print(f"[INFO] 备份文件已存在: {backup_path}")
        else:
            shutil.copy2(original_path, backup_path)
            print(f"[SUCCESS] 原始文件已备份: {backup_path}")
        return True
    else:
        print(f"[ERROR] 原始文件不存在: {original_path}")
        return False

def integrate_optimizations():
    """集成优化功能到现有文件"""
    original_file = os.path.join("wvs", "vuln", "validation_enhancer.py")
    
    if not os.path.exists(original_file):
        print(f"[ERROR] 文件不存在: {original_file}")
        return False
    
    # 读取原始文件内容
    with open(original_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print(f"[INFO] 原始文件大小: {len(content)} 字符")
    
    # 查找validate_sqli_time_based函数
    if "async def validate_sqli_time_based" not in content:
        print("[ERROR] 未找到validate_sqli_time_based函数")
        return False
    
    # 创建优化版本（简化集成）
    optimized_version = """async def validate_sqli_time_based(
        self,
        session,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        baseline_duration: float = 1.0
    ) -> ValidationResult:
        \"\"\"优化版时间盲注验证（集成优化算法）

        改进点：
        1. 消除重复请求浪费
        2. 支持有限并发测试
        3. IQR异常值检测
        4. 动态基线测量
        5. 优化置信度计算
        \"\"\"
        import statistics
        import asyncio
        
        # 优化配置
        test_count = self.config.get("time_test_count", 3)
        stddev_threshold = self.config.get("time_stddev_threshold", 0.3)
        min_delay = self.config.get("time_min_delay", 1.5)
        confidence_threshold = self.config.get("time_confidence_threshold", 0.7)
        concurrent_limit = min(2, test_count)  # 最大并发数
        
        # 动态基线测量（如果未提供）
        if baseline_duration <= 0.5:  # 基线过小，重新测量
            baseline_duration = await self._measure_dynamic_baseline(session, url, param, method)
        
        async def single_test(test_id):
            \"\"\"单次测试（无重复请求）\"\"\"
            try:
                # 构建请求
                if method.upper() == "GET":
                    params = {param: payload}
                    request_args = {"params": params}
                else:
                    data = {param: payload}
                    request_args = {"data": data}
                
                # 单次计时请求
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=20)
                start = time.perf_counter()
                async with session.request(method, url, **request_args, timeout=timeout) as resp:
                    await resp.read()  # 确保完成
                duration = time.perf_counter() - start
                
                # 自适应重试（超时时）
                if duration >= 18.0:  # 接近超时
                    await asyncio.sleep(0.5)
                    start_retry = time.perf_counter()
                    async with session.request(method, url, **request_args, 
                                             timeout=aiohttp.ClientTimeout(total=30)) as resp_retry:
                        await resp_retry.read()
                    return time.perf_counter() - start_retry
                
                return duration
                
            except asyncio.TimeoutError:
                return 25.0  # 超时惩罚值
            except Exception:
                return None
        
        # 并发执行测试
        tasks = []
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        async def bounded_test(test_id):
            async with semaphore:
                return await single_test(test_id)
        
        for i in range(test_count):
            tasks.append(bounded_test(i))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 收集有效结果
        durations = []
        for result in results:
            if isinstance(result, (int, float)):
                durations.append(result)
            elif result is not None:
                durations.append(result)
        
        # 数据有效性检查
        if len(durations) < 2:
            return ValidationResult(
                is_valid=False,
                confidence=0.0,
                evidence=f"有效测试数据不足: {len(durations)}/{test_count}",
                details={"durations": durations, "baseline": baseline_duration}
            )
        
        # IQR异常值过滤
        filtered_durations = self._iqr_filter_outliers(durations)
        if not filtered_durations:
            filtered_durations = durations
        
        # 计算统计指标
        mean_duration = statistics.mean(filtered_durations)
        median_duration = statistics.median(filtered_durations)
        
        if len(filtered_durations) > 1:
            stddev = statistics.stdev(filtered_durations)
            cv = stddev / mean_duration if mean_duration > 0 else 0  # 变异系数
        else:
            stddev = 0.0
            cv = 0.0
        
        # 稳定性评分
        stability_score = max(0, 1 - min(cv, 1.0))
        
        # 有效延迟
        effective_delay = mean_duration - baseline_duration
        
        # 优化置信度计算
        confidence = self._calculate_optimized_confidence(
            effective_delay, 
            stddev, 
            stability_score,
            min_delay,
            stddev_threshold,
            confidence_threshold
        )
        
        # 判定结果
        is_valid = confidence >= confidence_threshold and effective_delay >= min_delay
        
        # 生成证据
        evidence_parts = []
        if is_valid:
            evidence_parts.append(f"验证通过")
        evidence_parts.append(f"延迟: {effective_delay:.2f}s")
        evidence_parts.append(f"置信度: {confidence:.2f}")
        evidence_parts.append(f"稳定性: {stability_score:.2f}")
        if len(durations) != len(filtered_durations):
            evidence_parts.append(f"过滤异常值: {len(durations)-len(filtered_durations)}个")
        
        return ValidationResult(
            is_valid=is_valid,
            confidence=confidence,
            evidence="; ".join(evidence_parts),
            details={
                "original_durations": durations,
                "filtered_durations": filtered_durations,
                "mean": mean_duration,
                "median": median_duration,
                "stddev": stddev,
                "effective_delay": effective_delay,
                "baseline": baseline_duration,
                "stability_score": stability_score,
                "test_config": {
                    "test_count": test_count,
                    "concurrent_limit": concurrent_limit,
                    "min_delay": min_delay
                }
            }
        )"""
    
    # 添加辅助方法到类中
    helper_methods = """
    async def _measure_dynamic_baseline(self, session, url, param, method, samples=2):
        \"\"\"动态测量基线响应时间\"\"\"
        import asyncio
        import statistics
        
        durations = []
        for _ in range(samples):
            try:
                if method.upper() == "GET":
                    params = {param: "1"}  # 无害payload
                    request_args = {"params": params}
                else:
                    data = {param: "1"}
                    request_args = {"data": data}
                
                import aiohttp
                timeout = aiohttp.ClientTimeout(total=10)
                start = time.perf_counter()
                async with session.request(method, url, **request_args, timeout=timeout) as resp:
                    await resp.read()
                durations.append(time.perf_counter() - start)
                await asyncio.sleep(0.1)
            except Exception:
                durations.append(1.0)  # 默认值
        
        return statistics.median(durations) if durations else 1.0
    
    def _iqr_filter_outliers(self, data):
        \"\"\"IQR方法过滤异常值\"\"\"
        if len(data) < 4:
            return data
        
        import statistics
        q1 = statistics.quantiles(data, n=4)[0]
        q3 = statistics.quantiles(data, n=4)[2]
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        return [x for x in data if lower_bound <= x <= upper_bound]
    
    def _calculate_optimized_confidence(self, effective_delay, stddev, stability_score, 
                                       min_delay, stddev_threshold, base_threshold):
        \"\"\"优化置信度计算\"\"\"
        if effective_delay <= 0:
            return 0.0
        
        # 基于延迟的基础置信度
        delay_ratio = min(effective_delay / min_delay, 2.0)
        base_confidence = min(0.7 + (delay_ratio - 1) * 0.3, 0.95)
        
        # 稳定性调整
        if stddev < stddev_threshold:
            stability_bonus = stability_score * 0.2
        else:
            stability_bonus = 0.0
        
        confidence = base_confidence + stability_bonus
        return max(0.1, min(0.99, confidence))"""
    
    # 在类中添加新方法
    class_end_marker = "    # ==================== 私有方法 ===================="
    
    if class_end_marker in content:
        # 在类结束标记前插入辅助方法
        parts = content.split(class_end_marker)
        if len(parts) == 2:
            new_content = parts[0] + helper_methods + "\n\n" + class_end_marker + parts[1]
            
            # 替换原始函数
            import re
            # 找到原函数并替换
            pattern = r"async def validate_sqli_time_based\([\s\S]*?\) -> ValidationResult:[\s\S]*?(?=\n    async def|\n    # =|$)"
            new_content = re.sub(pattern, optimized_version, new_content, count=1)
            
            # 写入文件
            with open(original_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            print(f"[SUCCESS] 优化版验证器已集成到: {original_file}")
            print(f"[INFO] 文件大小: {len(new_content)} 字符")
            
            # 验证集成
            if "单次测试（无重复请求）" in new_content and "IQR方法过滤异常值" in new_content:
                print("[SUCCESS] 核心优化功能已确认集成")
                return True
            else:
                print("[WARNING] 部分优化功能可能未正确集成")
                return False
    
    print("[ERROR] 集成过程中出现问题")
    return False

def test_integration():
    """测试集成后的模块"""
    print("\n[TEST] 测试集成后的验证模块...")
    
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from wvs.vuln.validation_enhancer import ValidationEnhancer
        
        # 检查优化方法是否存在
        validator = ValidationEnhancer()
        
        # 检查方法
        required_methods = [
            '_measure_dynamic_baseline',
            '_iqr_filter_outliers', 
            '_calculate_optimized_confidence'
        ]
        
        missing_methods = []
        for method in required_methods:
            if not hasattr(validator, method):
                missing_methods.append(method)
        
        if missing_methods:
            print(f"[ERROR] 缺失方法: {missing_methods}")
            return False
        
        print("[SUCCESS] 所有优化方法已集成")
        
        # 检查配置参数
        config = {
            "time_test_count": 3,
            "time_stddev_threshold": 0.3,
            "time_min_delay": 1.5,
            "time_confidence_threshold": 0.7
        }
        
        validator_with_config = ValidationEnhancer(config)
        print("[SUCCESS] 优化配置参数可正常使用")
        
        print("\n[INFO] 集成验证结果:")
        print("  ✅ 优化版validate_sqli_time_based函数已集成")
        print("  ✅ 动态基线测量方法已添加")
        print("  ✅ IQR异常值过滤方法已添加")
        print("  ✅ 优化置信度计算方法已添加")
        print("  ✅ 配置参数系统正常工作")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] 集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主集成函数"""
    print("=" * 60)
    print("WVS v18.4 优化版验证增强集成工具")
    print("=" * 60)
    
    # 步骤1: 备份原始文件
    print("\n[STEP 1] 备份原始文件...")
    if not backup_original_file():
        print("[WARNING] 备份失败，继续集成可能覆盖原始文件")
        response = input("继续集成? (y/N): ")
        if response.lower() != 'y':
            print("[INFO] 集成已取消")
            return False
    
    # 步骤2: 集成优化功能
    print("\n[STEP 2] 集成优化功能...")
    if not integrate_optimizations():
        print("[ERROR] 集成失败")
        return False
    
    # 步骤3: 测试集成
    print("\n[STEP 3] 测试集成结果...")
    if not test_integration():
        print("[ERROR] 集成测试失败")
        return False
    
    print("\n" + "=" * 60)
    print("[SUCCESS] 优化版验证增强集成完成!")
    print("=" * 60)
    print("\n集成内容总结:")
    print("  1. ✅ 优化版时间盲注验证算法")
    print("  2. ✅ 消除重复请求浪费")
    print("  3. ✅ 支持有限并发测试")
    print("  4. ✅ IQR异常值检测")
    print("  5. ✅ 动态基线测量")
    print("  6. ✅ 优化置信度计算")
    print("\n下一步:")
    print("  1. 运行对比测试验证优化效果")
    print("  2. 将优化扩展到CMDI和XSS验证")
    print("  3. 更新文档记录优化改进")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)